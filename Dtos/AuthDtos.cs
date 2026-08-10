namespace EndpointSecurityAPI.Dtos;

public record LoginRequestDto(string Username, string Password);

public record LoginResponseDto(string Token, DateTime ExpiresUtc, string Username, string Role);

public record CreateEnrollmentTokenRequestDto(string Label);

/// <summary>RawToken is only ever returned once, at creation time — it is never stored or retrievable again.</summary>
public record CreateEnrollmentTokenResponseDto(int Id, string Label, string RawToken, DateTime CreatedUtc);

public record EnrollmentTokenSummaryDto(int Id, string Label, DateTime CreatedUtc, bool IsActive, int DeviceCount);
