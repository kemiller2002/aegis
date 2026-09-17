namespace Aegis

open System

/// Deferred delivery for a sink that is temporarily unavailable. Queued
/// entries hold the already-serialized, already-redacted payload, so identity,
/// timestamps, correlation ids, redaction state and schema version are
/// preserved by construction rather than reconstructed later.
/// Requirement: logging 20.
module Offline =

    type Entry =
        { EventId: EventId
          /// Serialized after redaction; never re-derived on the way out.
          Payload: string
          /// Explicit ordering metadata, because timestamps alone may not be
          /// sufficient to reconstruct sequence. Requirement: logging 33.
          Sequence: int64 }

    type Queue =
        { Entries: Entry list
          NextSequence: int64
          Capacity: int
          /// Entries dropped because the queue was full, so loss is visible
          /// rather than silent. Requirement: core 7.
          Dropped: int }

    let create capacity =
        { Entries = []
          NextSequence = 1L
          Capacity = capacity
          Dropped = 0 }

    /// Append preserving order. A full queue drops the oldest entry and counts
    /// it: bounded memory is required, silent loss is not acceptable.
    let enqueue (eventId: EventId) (payload: string) (queue: Queue) =
        let entry =
            { EventId = eventId
              Payload = payload
              Sequence = queue.NextSequence }

        let appended = queue.Entries @ [ entry ]

        if List.length appended <= queue.Capacity then
            { queue with
                Entries = appended
                NextSequence = queue.NextSequence + 1L }
        else
            { queue with
                Entries = List.tail appended
                NextSequence = queue.NextSequence + 1L
                Dropped = queue.Dropped + 1 }

    let count (queue: Queue) = List.length queue.Entries

    /// Result of a drain attempt. Entries that were not delivered stay queued
    /// in their original order, so a partial outage cannot reorder history.
    type DrainResult =
        { Queue: Queue
          Delivered: EventId list
          Failed: (EventId * string) option }

    /// Deliver in sequence order, stopping at the first failure so ordering is
    /// never violated by skipping ahead. Asynchronous, so flushing a backlog
    /// does not block the caller either.
    /// Requirements: logging 18, 19, 20, 33.
    let drainAsync (write: string -> Async<unit>) (queue: Queue) =
        let rec loop remaining delivered =
            async {
                match remaining with
                | [] ->
                    return
                        { Queue = { queue with Entries = [] }
                          Delivered = List.rev delivered
                          Failed = None }
                | (entry: Entry) :: rest ->
                    let! failure =
                        async {
                            try
                                do! write entry.Payload
                                return None
                            with ex ->
                                return Some ex.Message
                        }

                    match failure with
                    | None -> return! loop rest (entry.EventId :: delivered)
                    | Some message ->
                        return
                            { Queue = { queue with Entries = entry :: rest }
                              Delivered = List.rev delivered
                              Failed = Some(entry.EventId, message) }
            }

        loop (queue.Entries |> List.sortBy (fun e -> e.Sequence)) []

    /// Awaits the drain. For callers that need the outcome, such as a
    /// controlled shutdown.
    let drain (write: string -> unit) (queue: Queue) =
        drainAsync (fun payload -> async { write payload }) queue |> Async.RunSynchronously

    /// Idempotency keys for duplicate-write protection at the sink.
    /// Requirement: logging 32.
    let pendingIds (queue: Queue) =
        queue.Entries |> List.sortBy (fun e -> e.Sequence) |> List.map (fun e -> e.EventId)
