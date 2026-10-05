namespace Aegis.Store.GitHub

open System
open Aegis

/// GitHub-backed durable store: one immutable file per event, so writes never
/// rewrite a growing log and merge conflicts stay rare.
///
/// This adapter deliberately does not contain GitHub API code. The repository
/// operations are injected, because the integration assembly owns that client
/// and Aegis must not duplicate it.
/// Requirements: logging 4, 7, 8, 9, 26, 34, 35, 36, 43.
module GitHubStore =

    /// Adapter-level policy, not core behaviour. Requirement: logging 35.
    type CommitStrategy =
        /// One commit per event: simplest history, most API calls.
        | OnePerCommit
        /// Group up to n events into one commit. Requirement: logging 19.
        | Batched of maxPerCommit: int

    /// Requirement: logging 9.
    type Config =
        { Owner: string
          Repository: string
          Branch: string
          RootPath: string
          CommitStrategy: CommitStrategy
          /// Default retention for events this adapter stores, when an event
          /// does not carry its own intent. Requirement: logging 26.
          Retention: Aegis.Retention
          /// Used only when an event carries no timestamp of its own.
          Now: unit -> DateTimeOffset }

    /// The repository operations this adapter needs. Supplied by the GitHub
    /// integration assembly. Requirement: logging 43.
    type Operations =
        { /// Whether a path already holds an event file.
          Exists: string -> Async<Result<bool, string>>
          /// Commit one file. path -> content -> commit message.
          PutFile: string -> string -> string -> Async<Result<unit, string>>
          /// Commit several files together. Requirement: logging 35.
          PutFiles: (string * string) list -> string -> Async<Result<unit, string>>
          /// Every stored file under a path prefix, as (path, content).
          ListPrefix: string -> Async<Result<(string * string) list, string>> }

    let defaults owner repository =
        { Owner = owner
          Repository = repository
          Branch = "main"
          RootPath = "aegis"
          CommitStrategy = OnePerCommit
          Retention = Aegis.RetainIndefinitely
          Now = fun () -> DateTimeOffset.UtcNow }

    /// Date-bucketed path holding one immutable event file. The file name is
    /// the sortable event id alone: it carries no message text and nothing
    /// sensitive. Requirements: logging 7, 8.
    let pathFor (config: Config) (at: DateTimeOffset) (eventId: EventId) =
        let utc = at.ToUniversalTime()
        $"%s{config.RootPath}/%04d{utc.Year}/%02d{utc.Month}/%02d{utc.Day}/%s{eventId.Value}.json"

    /// The path an already-serialized event belongs at, taken from its own
    /// timestamp so a deferred event lands in the bucket it happened in
    /// rather than the bucket it was flushed in. Requirement: logging 20.
    let pathForPayload (config: Config) (eventId: EventId) (payload: string) =
        let at =
            match Store.index payload with
            | Ok indexed -> indexed.Timestamp |> Option.defaultWith config.Now
            | Result.Error _ -> config.Now()

        pathFor config at eventId

    let private message (config: Config) (eventId: EventId) =
        $"aegis: record event {eventId.Value}"

    let private batchMessage (count: int) = $"aegis: record {count} events"

    let private groups strategy items =
        match strategy with
        | OnePerCommit -> items |> List.map List.singleton
        | Batched size when size > 0 -> items |> List.chunkBySize size
        | Batched _ -> [ items ]

    /// What a path already holds, relative to the payload about to be
    /// written there.
    type private Existing =
        | Vacant
        /// The identical record is already stored: a replay, so writing again
        /// is unnecessary and reporting a conflict would be wrong.
        | AlreadyStored
        | Occupied

    let private inspect (ops: Operations) (path: string) (payload: string) =
        async {
            match! ops.Exists path with
            | Result.Error reason -> return Result.Error(Store.Unavailable reason)
            | Ok false -> return Ok Vacant
            | Ok true ->
                match! ops.ListPrefix path with
                | Result.Error reason -> return Result.Error(Store.Unavailable reason)
                | Ok files ->
                    let identical = files |> List.exists (fun (p, content) -> p = path && content = payload)
                    return Ok(if identical then AlreadyStored else Occupied)
        }

    /// Every stored record under the root, with the ones that could not be
    /// read listed rather than dropped. Requirements: logging 27, 29, 40.
    let queryDetailed (config: Config) (ops: Operations) (q: Store.Query) =
        async {
            match! ops.ListPrefix config.RootPath with
            | Result.Error reason -> return Result.Error(Store.Unavailable reason)
            | Ok files ->
                // Search structured fields, never the human-readable text.
                // Requirements: additional 41; logging 27, 29.
                let indexed =
                    files
                    |> List.sortBy fst // path is date-bucketed then sortable id
                    |> List.map (fun (path, content) -> path, content, Store.index content)

                return
                    Ok
                        { Store.Matched =
                            indexed
                            |> List.choose (fun (_, content, result) ->
                                match result with
                                | Ok entry when Store.matches q entry -> Some content
                                | _ -> None)
                          Store.Unreadable =
                            indexed
                            |> List.choose (fun (path, _, result) ->
                                match result with
                                | Result.Error (Store.Malformed reason) -> Some { Store.Path = path; Store.Reason = reason }
                                | Result.Error other -> Some { Store.Path = path; Store.Reason = string other }
                                | Ok _ -> None) }
        }

    /// Build the store. Append refuses to overwrite: because event files are
    /// immutable and uniquely named, a different record at the same path is
    /// abnormal and is reported rather than resolved by overwriting. The
    /// identical record already being present is a replay, and succeeds
    /// without writing, so retrying an append is idempotent.
    /// Requirements: logging 32, 36.
    let create (config: Config) (ops: Operations) : Store.T =
        let appendOne (eventId: EventId) (payload: string) =
            async {
                let path = pathForPayload config eventId payload

                match! inspect ops path payload with
                | Result.Error failure -> return Result.Error failure
                | Ok AlreadyStored -> return Ok()
                | Ok Occupied -> return Result.Error(Store.Conflict path)
                | Ok Vacant ->
                    match! ops.PutFile path payload (message config eventId) with
                    | Ok () -> return Ok()
                    | Result.Error reason -> return Result.Error(Store.Unavailable reason)
            }

        let appendMany (items: (EventId * string) list) =
            async {
                // Conflicts are checked before any commit, so a batch cannot
                // half-apply because of a known collision. Records already
                // stored by an earlier, partly applied attempt are skipped,
                // so replaying the whole batch completes it rather than
                // conflicting with itself.
                let paths = items |> List.map (fun (id, payload) -> pathForPayload config id payload, payload)

                let rec checkAll remaining pending =
                    async {
                        match remaining with
                        | [] -> return Ok(List.rev pending)
                        | (path, payload) :: rest ->
                            match! inspect ops path payload with
                            | Result.Error failure -> return Result.Error failure
                            | Ok Occupied -> return Result.Error(Store.Conflict path)
                            | Ok AlreadyStored -> return! checkAll rest pending
                            | Ok Vacant -> return! checkAll rest ((path, payload) :: pending)
                    }

                match! checkAll paths [] with
                | Result.Error failure -> return Result.Error failure
                | Ok pending ->
                    let rec commit remaining =
                        async {
                            match remaining with
                            | [] -> return Ok()
                            | (chunk: (string * string) list) :: rest ->
                                let! outcome =
                                    match chunk with
                                    | [ (path, payload) ] ->
                                        ops.PutFile path payload (batchMessage 1)
                                    | many -> ops.PutFiles many (batchMessage (List.length many))

                                match outcome with
                                | Ok () -> return! commit rest
                                | Result.Error reason -> return Result.Error(Store.Unavailable reason)
                        }

                    return! commit (groups config.CommitStrategy pending)
            }

        { Append = appendOne
          AppendBatch = appendMany
          // Partial failure is not success: an unreadable record fails the
          // query, naming it. `queryDetailed` returns the readable part
          // alongside the list of unreadable records.
          Query = fun q -> async { let! outcome = queryDetailed config ops q in return Result.bind Store.complete outcome } }

    /// The id a serialized event already carries. Aegis serializes the event
    /// id into every payload, so a retry of the same event reuses it; the
    /// minted id is only a fallback for a payload that carries none.
    let private eventIdOf (nextId: unit -> EventId) (payload: string) =
        match Store.index payload with
        | Ok indexed -> indexed.EventId
        | Result.Error _ -> nextId ()

    /// A sink that writes through the store, queueing when the store is
    /// unavailable so a transient outage defers rather than loses events.
    /// Events are stored and queued under the id inside their payload, so a
    /// deferred or partly committed write replays idempotently.
    /// Asynchronous throughout: nothing here blocks the caller.
    /// Requirements: logging 15, 18, 19, 20, 32.
    let sink (store: Store.T) (level: Sinks.Level) (queue: Offline.Queue ref) (nextId: unit -> EventId) =
        let writeOne payload =
            async {
                let eventId = eventIdOf nextId payload

                match! store.Append eventId payload with
                | Ok () -> return ()
                | Result.Error (Store.Conflict path) ->
                    // Abnormal: a different record already holds this
                    // uniquely named path. Surface it rather than overwrite.
                    return failwith $"conflict: {path} already exists"
                | Result.Error failure ->
                    // Defer rather than lose it, then tell the runtime this
                    // sink did not persist.
                    queue.Value <- Offline.enqueue eventId payload queue.Value
                    return failwith $"deferred: {failure}"
            }

        { Sinks.Name = "github"
          Sinks.Level = level
          Sinks.Capabilities =
            [ Sinks.SupportsDurableWrite
              Sinks.SupportsQuery
              Sinks.SupportsBatch
              Sinks.SupportsOfflineQueue
              Sinks.SupportsIdempotency ]
          Sinks.Write = writeOne
          Sinks.WriteBatch =
            Some(fun payloads ->
                async {
                    let items = payloads |> List.map (fun payload -> eventIdOf nextId payload, payload)

                    match! store.AppendBatch items with
                    | Ok () -> return ()
                    | Result.Error failure ->
                        // The whole batch is queued under its own ids. Any
                        // part that did commit is recognised on replay and
                        // not written twice.
                        for id, payload in items do
                            queue.Value <- Offline.enqueue id payload queue.Value

                        return failwith $"deferred batch: {failure}"
                }) }
