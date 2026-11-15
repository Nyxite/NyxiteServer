using System.Text.Json;
using System.Text.Json.Serialization;

namespace Nyxite.Contracts.Structure;

// Wire shapes of the structure endpoints (openapi/v1.yaml, tag "structure"), shared with the desktop client.
// Names, metadata and wrapped keys are client-side ciphertext, base64url without padding. Request fields are nullable
// where the server validates them itself and answers 400 validation_failed.

/// <summary>
/// A PATCH field that tells "not sent" apart from "sent as null", for fields where null is a value of its own
/// (a folder moved to the project root, metadata cleared, a folder's sync policy reset to inherit).
/// </summary>
[JsonConverter(typeof(PatchConverterFactory))]
public readonly struct Patch<T>(T? value)
{
    public bool IsSet { get; } = true;
    public T? Value { get; } = value;
}

public sealed class PatchConverterFactory : JsonConverterFactory
{
    public override bool CanConvert(Type type) => type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Patch<>);

    public override JsonConverter CreateConverter(Type type, JsonSerializerOptions options) =>
        (JsonConverter)Activator.CreateInstance(typeof(PatchConverter<>).MakeGenericType(type.GetGenericArguments()[0]))!;

    private sealed class PatchConverter<T> : JsonConverter<Patch<T>>
    {
        public override bool HandleNull => true;

        public override Patch<T> Read(ref Utf8JsonReader reader, Type type, JsonSerializerOptions options) =>
            new(JsonSerializer.Deserialize<T>(ref reader, options));

        public override void Write(Utf8JsonWriter writer, Patch<T> value, JsonSerializerOptions options) =>
            JsonSerializer.Serialize(writer, value.Value, options);
    }
}

/// <summary>A key wrapped to one member (HPKE). The server stores it and cannot open it.</summary>
public sealed record WrappedKeyRequest(Guid KeyId, Guid? MemberId, string? Ciphertext, int Generation, string? AlgId);

public sealed record WrappedKeyDto(Guid KeyId, Guid? MemberId, string Ciphertext, int Generation, string AlgId);

public sealed record WrappedKeysDto(IReadOnlyList<WrappedKeyDto> Items);

public sealed record PageDto<T>(IReadOnlyList<T> Items, string? NextCursor);

public sealed record CreateProjectRequest(Guid Id, string? NameEnc, string? MetadataEnc, string? SyncPolicy, WrappedKeyRequest? OwnerWrappedKey);

public sealed record UpdateProjectRequest(string? NameEnc, Patch<string?> MetadataEnc, string? SyncPolicy);

public sealed record ProjectDto(Guid Id, Guid OwnerId, string NameEnc, string? MetadataEnc, string SyncPolicy, int KeyGeneration,
    DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, DateTimeOffset? DeletedAt, WrappedKeyDto? WrappedKey);

public sealed record CreateFolderRequest(Guid Id, Guid ProjectId, Guid? ParentFolderId, string? NameEnc, string? MetadataEnc, string? SyncPolicy,
    WrappedKeyRequest? OwnerWrappedKey);

public sealed record UpdateFolderRequest(string? NameEnc, Patch<Guid?> ParentFolderId, Patch<string?> MetadataEnc, Patch<string?> SyncPolicy);

public sealed record FolderDto(Guid Id, Guid ProjectId, Guid? ParentFolderId, string NameEnc, string? MetadataEnc, string? SyncPolicy, int KeyGeneration,
    DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, DateTimeOffset? DeletedAt, WrappedKeyDto? WrappedKey);

public sealed record CreateFileRequest(Guid Id, Guid ProjectId, Guid? FolderId, string? NameEnc, string? ContentType, string? SyncPolicy,
    string? MetadataEnc, Guid? CrdtDocId, WrappedKeyRequest? OwnerWrappedKey);

public sealed record UpdateFileRequest(string? NameEnc, string? SyncPolicy, Patch<Guid?> ParentFolderId, Patch<string?> MetadataEnc);

public sealed record FileDto(Guid Id, Guid ProjectId, Guid? FolderId, Guid OwnerId, string NameEnc, string? MetadataEnc, string ContentType,
    string SyncPolicy, long? CurrentVersionSeq, Guid? CrdtDocId, int KeyGeneration,
    DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, DateTimeOffset? DeletedAt, WrappedKeyDto? WrappedKey, bool RotationPending = false);

/// <summary>
/// One entry of the Trash view: something the caller deleted directly, with what went to Trash along with it. Exactly
/// one of <see cref="Project"/>, <see cref="Folder"/> and <see cref="File"/> is set, named by <see cref="Entity"/>.
/// </summary>
public sealed record TrashItemDto(string Entity, DateTimeOffset DeletedAt, DateTimeOffset RestorableUntil, int Folders, int Files,
    ProjectDto? Project, FolderDto? Folder, FileDto? File);

/// <summary>Asks for the caller's wrapped keys of many objects at once.</summary>
public sealed record KeyLookupRequest(IReadOnlyList<Guid>? ProjectIds, IReadOnlyList<Guid>? FolderIds, IReadOnlyList<Guid>? FileIds);

public sealed record ObjectKeysDto(string Entity, Guid Id, IReadOnlyList<WrappedKeyDto> WrappedKeys);

public sealed record KeyLookupDto(IReadOnlyList<ObjectKeysDto> Items);
