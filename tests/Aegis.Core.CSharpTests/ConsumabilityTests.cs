using System;
using System.Linq;
using Aegis;
using Microsoft.FSharp.Collections;
using Microsoft.FSharp.Core;
using Xunit;

namespace Aegis.CSharpTests;

/// <summary>
/// Aegis is F#-first, but core 36 requires it to be usable from C#. This
/// project is the verification of that claim rather than an assertion of it:
/// if a change makes the public surface unusable from C#, this stops
/// compiling.
///
/// It also documents the friction honestly. F# records expose positional
/// constructors, options must be built through FSharpOption, and lists and
/// maps must be built through ListModule and MapModule. Those are the
/// "unnecessary F# constructs" core 36 warns about, and the helpers at the
/// bottom of this file are what a real C# consumer would end up writing.
/// </summary>
public class ConsumabilityTests
{
    private static readonly DateTimeOffset At = new(2026, 9, 17, 17, 0, 0, TimeSpan.Zero);

    [Fact]
    public void A_fault_can_be_constructed_from_csharp()
    {
        var fault = MakeFault("CHRONA.GITHUB.LOAD_FAILED");
        Assert.Equal("CHRONA.GITHUB.LOAD_FAILED", fault.Code.Value);
        Assert.Equal("Chrona.TimeEntry.Load", fault.Operation);
        Assert.Equal(FailureDomain.IntegrationDomain, fault.Domain);
    }

    [Fact]
    public void An_event_can_be_serialized_from_csharp()
    {
        var recorded = AegisEvent.NewFaultRecorded(MakeFault("CHRONA.GITHUB.LOAD_FAILED"));
        var payload = Serialization.@event(Redaction.defaultRules, EventId.NewEventId("01E1"), recorded);

        Assert.Contains("aegis/event/v1", payload);
        Assert.Contains("CHRONA.GITHUB.LOAD_FAILED", payload);
    }

    [Fact]
    public void Reporting_through_a_collector_works_from_csharp()
    {
        var collector = new Sinks.Collector(Some(10));
        var config = MakeConfig(collector.Sink(FSharpOption<Sinks.Level>.None));

        Aegis.report(config, AegisEvent.NewFaultRecorded(MakeFault("CHRONA.GITHUB.LOAD_FAILED")));

        Assert.Single(collector.Events);
        Assert.Contains("CHRONA.GITHUB.LOAD_FAILED", collector.Codes);
    }

    [Fact]
    public void Redaction_still_applies_when_driven_from_csharp()
    {
        var collector = new Sinks.Collector(Some(10));
        var config = MakeConfig(collector.Sink(FSharpOption<Sinks.Level>.None));

        var context = MapOf(
            Tuple.Create("github_token", ContextValue.NewPublic("ghp_leaked")),
            Tuple.Create("repository", ContextValue.NewPublic("aegis")));

        var leaky = MakeFault("CHRONA.GITHUB.LOAD_FAILED", context);
        Aegis.report(config, AegisEvent.NewFaultRecorded(leaky));

        var payload = collector.Events.First();
        Assert.DoesNotContain("ghp_leaked", payload);
        Assert.Contains("aegis", payload);
    }

    [Fact]
    public void The_named_sinks_are_constructible_from_csharp()
    {
        Assert.Equal("console", Sinks.console.Name);
        Assert.Equal("no-op", Sinks.noOp.Name);
        Assert.Equal("stderr", Sinks.standardError.Name);
    }

    [Fact]
    public void A_stored_event_can_be_indexed_from_csharp()
    {
        var recorded = AegisEvent.NewFaultRecorded(MakeFault("CHRONA.GITHUB.LOAD_FAILED"));
        var payload = Serialization.@event(Redaction.defaultRules, EventId.NewEventId("01E1"), recorded);

        var indexed = Store.index(payload);
        Assert.True(indexed.IsOk);
        Assert.Equal("FaultRecorded", indexed.ResultValue.EventType);
    }

    [Fact]
    public void The_health_projection_is_readable_from_csharp()
    {
        var observations = ListOf(Tuple.Create(At, Sinks.Outcome.NewWritten("github")));
        var health = Sinks.observe(observations);
        var projection = Health.project(false, 100, 0, health);

        Assert.Equal(Health.State.Healthy, projection.State);
    }

    [Fact]
    public void A_presentation_can_be_built_and_read_from_csharp()
    {
        var presented = Presentation.present("Unable to load time entries", MakeFault("CHRONA.GITHUB.LOAD_FAILED"));
        Assert.Equal("GitHub could not be reached.", presented.Message);
        Assert.StartsWith("AG-", presented.Reference);
    }

    [Fact]
    public void Contribution_provenance_can_be_attached_and_read_from_csharp()
    {
        // AEG-PROV-012: the additive provenance surface is usable from C#.
        var human = ProvenanceIdentity.human("kevin");
        var key = Provenance.outsideExecutionKey(At, human);
        var contribution = Provenance.contribution(key, human, At, ListOf("reviewed"));
        var built = Provenance.build(ListOf(contribution), ListOf("git:commit/5e1f0c2"));
        Assert.True(built.IsOk);

        var attributed = Provenance.attach(
            built.ResultValue,
            AegisEvent.NewFaultAcknowledged(FaultId.NewFaultId("01F1"), RecoveryActor.Operator, At));
        var payload = Serialization.attributedEvent(Redaction.defaultRules, EventId.NewEventId("01E2"), attributed);

        var read = Store.provenanceOf(payload);
        Assert.True(read.IsOk);
        Assert.Equal(built.ResultValue, read.ResultValue.Value);
        Assert.Equal(key, Provenance.withRole("reviewed", read.ResultValue.Value).Head.Key);

        var malformed = Provenance.receive("{\"schema\":\"praxis.provenance/1\"}");
        Assert.True(malformed.IsError);
    }

    // ---------------------------------------------------------------- helpers
    //
    // What a C# consumer has to write. Kept together so the cost of the
    // cross-language surface is visible in one place rather than spread
    // through the tests.

    private static FSharpOption<T> Some<T>(T value) => FSharpOption<T>.Some(value);

    private static FSharpList<T> ListOf<T>(params T[] items) => ListModule.OfSeq(items);

    private static FSharpMap<string, ContextValue> MapOf(params Tuple<string, ContextValue>[] pairs) =>
        MapModule.OfSeq(pairs);

    private static AegisConfig MakeConfig(params Sinks.Sink[] sinks) =>
        new(
            "Chrona",
            Some("1.4.2"),
            ListModule.OfSeq(sinks),
            Redaction.defaultRules,
            FuncConvert.FromAction<string>(_ => { }),
            PersistenceMode.Blocking,
            FuncConvert.FromFunc(() => At),
            FuncConvert.FromFunc(() => Tuple.Create(1L, 2L)));

    private static Fault MakeFault(string code) =>
        MakeFault(code, MapModule.Empty<string, ContextValue>());

    private static Fault MakeFault(string code, FSharpMap<string, ContextValue> context) =>
        new(
            FaultId.NewFaultId("01F1"),
            CorrelationId.NewCorrelationId("CORR1"),
            At,
            "Chrona",
            Some("1.4.2"),
            "Chrona.TimeEntry.Load",
            FailureCategory.IntegrationFailure,
            FaultCode.NewFaultCode(code),
            FaultSeverity.Warning,
            FaultImpact.OperationOnly,
            FailureDomain.IntegrationDomain,
            BlastRadius.OneOperation,
            Retention.DiagnosticOnly,
            Persistence.Transient,
            Some("GitHubIntegration"),
            ListOf("Chrona"),
            "GitHub could not be reached.",
            FSharpOption<string>.None,
            context,
            RecoveryPolicy.NoRecovery,
            FaultDefaults.noDiagnostics,
            FSharpOption<FaultCause>.None);
}
