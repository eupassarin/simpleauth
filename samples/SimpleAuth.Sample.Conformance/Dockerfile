FROM mcr.microsoft.com/dotnet/sdk:10.0-preview AS build
WORKDIR /src

# Copy solution and project files
COPY Directory.Build.props ./
COPY src/SimpleAuth.Storage.Abstractions/SimpleAuth.Storage.Abstractions.csproj src/SimpleAuth.Storage.Abstractions/
COPY src/SimpleAuth.Storage.InMemory/SimpleAuth.Storage.InMemory.csproj src/SimpleAuth.Storage.InMemory/
COPY src/SimpleAuth.Core/SimpleAuth.Core.csproj src/SimpleAuth.Core/
COPY samples/SimpleAuth.Sample.Conformance/SimpleAuth.Sample.Conformance.csproj samples/SimpleAuth.Sample.Conformance/

# Restore
RUN dotnet restore samples/SimpleAuth.Sample.Conformance/SimpleAuth.Sample.Conformance.csproj

# Copy everything and publish
COPY src/ src/
COPY samples/SimpleAuth.Sample.Conformance/ samples/SimpleAuth.Sample.Conformance/

RUN dotnet publish samples/SimpleAuth.Sample.Conformance/SimpleAuth.Sample.Conformance.csproj \
    -c Release -o /app --no-restore

# Runtime image
FROM mcr.microsoft.com/dotnet/aspnet:10.0-preview AS runtime
WORKDIR /app
COPY --from=build /app .

ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production

EXPOSE 8080
ENTRYPOINT ["dotnet", "SimpleAuth.Sample.Conformance.dll"]
