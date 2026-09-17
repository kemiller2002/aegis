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

    /// Retention intent travels with the configuration; enforcement is the
    /// adapter's. Requirement: logging 26.
    type Retention =
        | RetainIndefinitely
        | RetainDays of int
        | ArchiveAfterDays of int
        | AuditRequired
        | DiagnosticOnly

    /// Requirement: logging 9.
    type Config =
        { Owner: string
          Repository: string
          Branch: string
          RootPath: string
          CommitStrategy: CommitStrategy
          Retention: Retention
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
          Retention = RetainIndefinitely
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

    /// Build the store. Append refuses to overwrite: because event files are
    /// immutable and uniquely named, a collision is abnormal and is reported
    /// rather than resolved by overwriting. Requirement: logging 36.
    let create (config: Config) (ops: Operations) : Store.T =
        let appendOne (eventId: EventId) (payload: string) =
            async {
                let path = pathForPayload config eventId payload

                match! ops.Exists path with
                | Result.Error reason -> return Result.Error(Store.Unavailable reason)
                | Ok true -> return Result.Error(Store.Conflict path)
                | Ok false ->
                    match! ops.PutFile path payload (message config eventId) with
                    | Ok () -> return Ok()
                    | Result.Error reason -> return Result.Error(Store.Unavailable reason)
            }

        let appendMany (items: (EventId * string) list) =
            async {
                // Conflicts are checked before any commit, so a batch cannot
                // half-apply because of a known collision.
                let paths = items |> List.map (fun (id, payload) -> pathForPayload config id payload, payload)

                let rec checkAll remaining =
                    async {
                        match remaining with
                        | [] -> return Ok()
                        | (path, _) :: rest ->
                            match! ops.Exists path with
                            | Result.Error reason -> return Result.Error(Store.Unavailable reason)
                            | Ok true -> return Result.Error(Store.Conflict path)
                            | Ok false -> return! checkAll rest
                    }

                match! checkAll paths with
                | Result.Error failure -> return Result.Error failure
                | Ok () ->
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

                    return! commit (groups config.CommitStrategy paths)
            }

        let query (q: Store.Query) =
            async {
                match! ops.ListPrefix config.RootPath with
                | Result.Error reason -> return Result.Error(Store.Unavailable reason)
                | Ok files ->
                    // Search structured fields, never the human-readable text.
                    // Requirements: additional 41; logging 27, 29.
                    let matched =
                        files
                        |> List.sortBy fst // path is date-bucketed then sortable id
                        |> List.choose (fun (_, content) ->
                            match Store.index content with
                            | Ok indexed when Store.matches q indexed -> Some content
                            | Ok _ -> None
                            | Result.Error _ -> None)

                    return Ok matched
            }

        { Append = appendOne
          AppendBatch = appendMany
          Query = query }

    /// A sink that writes through the store, queueing when the store is
    /// unavailable so a transient outage defers rather than loses events.
    /// Asynchronous throughout: nothing here blocks the caller.
    /// Requirements: logging 15, 18, 19, 20.
    let sink (store: Store.T) (level: Sinks.Level) (queue: Offline.Queue ref) (nextId: unit -> EventId) =
        let writeOne payload =
            async {
                let eventId = nextId ()

                match! store.Append eventId payload with
                | Ok () -> return ()
                | Result.Error (Store.Conflict path) ->
                    // Abnormal: a uniquely named immutable record already
                    // exists. Surface it rather than overwrite.
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
                    let items = payloads |> List.map (fun payload -> nextId (), payload)

                    match! store.AppendBatch items with
                    | Ok () -> return ()
                    | Result.Error failure ->
                        for id, payload in items do
                            queue.Value <- Offline.enqueue id payload queue.Value

                        return failwith $"deferred batch: {failure}"
                }) }
