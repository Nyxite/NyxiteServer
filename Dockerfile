# Nyxite server image (14 §14.2). Multi-arch (linux/amd64, linux/arm64): the build stage runs on the build host's
# architecture and cross-publishes for the target, so no emulation is needed for the compile.
# The same image serves the API and runs the migration step: `nyxite-server migrate` (14 §14.4).
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG TARGETARCH
WORKDIR /src

# Restore first, from the project files alone, so the layer is reused until a dependency changes.
COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/Nyxite.Server/Nyxite.Server.csproj src/Nyxite.Server/
COPY src/Nyxite.Application/Nyxite.Application.csproj src/Nyxite.Application/
COPY src/Nyxite.Persistence/Nyxite.Persistence.csproj src/Nyxite.Persistence/
COPY src/Nyxite.Domain/Nyxite.Domain.csproj src/Nyxite.Domain/
COPY src/Nyxite.Contracts/Nyxite.Contracts.csproj src/Nyxite.Contracts/
COPY src/Nyxite.Crypto/Nyxite.Crypto.csproj src/Nyxite.Crypto/
COPY src/Nyxite.BlobStore/Nyxite.BlobStore.csproj src/Nyxite.BlobStore/
RUN dotnet restore src/Nyxite.Server/Nyxite.Server.csproj -a $TARGETARCH

COPY openapi/ openapi/
COPY src/ src/
RUN dotnet publish src/Nyxite.Server/Nyxite.Server.csproj -c Release -a $TARGETARCH --no-restore -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
# The Postgres driver probes for Kerberos at its first connection and logs an error when the library is missing.
RUN apt-get update && apt-get install -y --no-install-recommends libgssapi-krb5-2 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app ./
# The base image's unprivileged user: the server needs no root and writes nothing into its own directory.
USER $APP_UID
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "Nyxite.Server.dll"]
