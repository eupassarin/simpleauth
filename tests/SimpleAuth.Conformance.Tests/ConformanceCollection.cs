using Xunit;

namespace SimpleAuth.Conformance.Tests;

/// <summary>
/// xUnit collection that shares a single <see cref="ConformanceFixture"/> across all test classes.
/// This avoids starting a new TestServer for every test class (faster execution).
/// </summary>
[CollectionDefinition("Conformance")]
public sealed class ConformanceCollection : ICollectionFixture<ConformanceFixture>;
