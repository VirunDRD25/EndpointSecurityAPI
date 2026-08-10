namespace EndpointSecurityAPI.Services;

/// <summary>
/// Single source of truth for "is this software authorized" — used both
/// during report ingestion and when an admin edits the approved list on
/// the Configuration page. Matching is substring/case-insensitive (e.g.
/// "Zoom" in the approved list matches "Zoom Workplace"), same rule the
/// agent originally used locally.
/// </summary>
public static class SoftwareAuthorizationHelper
{
    public static bool IsApproved(string softwareName, List<string> approvedList)
    {
        return approvedList.Any(a => softwareName.Contains(a, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Empty approved list means "no allowlist configured" — deliberately
    /// does NOT flag everything as unauthorized in that case (matches the
    /// agent's original fail-open behavior).
    /// </summary>
    public static List<string> DetermineUnauthorized(List<string> installedSoftware, List<string> approvedList)
    {
        if (approvedList.Count == 0) return new List<string>();
        return installedSoftware.Where(s => !IsApproved(s, approvedList)).ToList();
    }
}