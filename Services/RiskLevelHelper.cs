namespace EndpointSecurityAPI.Services;

/// <summary>
/// Single source of truth for turning a risk score into a Low/Medium/High
/// label. Used by DevicesController, DashboardController, and anywhere else
/// that needs to bucket a score — keeping this in one place avoids the
/// dashboard's summary counts and a device's own badge ever disagreeing.
/// The High cutoff is configurable (SystemSettings.AlertThresholds.HighRiskThreshold);
/// Low/Medium split at 25 is a fixed, documented default.
/// </summary>
public static class RiskLevelHelper
{
    public const int LowMediumBoundary = 25;

    public static string Classify(int score, int highRiskThreshold)
    {
        if (score >= highRiskThreshold) return "High";
        if (score >= LowMediumBoundary) return "Medium";
        return "Low";
    }
}
