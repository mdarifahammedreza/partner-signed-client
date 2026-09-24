// .NET equivalent of examples/test-handoff-hmac.js and examples/test-handoff-ed25519.js.
// Reads the same repo-root .env as the Node examples.
//
//   dotnet run --project dotnet/examples/HandoffExample -- hmac
//   dotnet run --project dotnet/examples/HandoffExample -- ed25519

using System.Text.Json;
using DanumAi.PartnerSignedClient;

LoadEnv();

var scheme = args.FirstOrDefault()?.ToLowerInvariant() switch
{
    "ed25519" => SigningScheme.Ed25519,
    "hmac" or null => SigningScheme.Hmac,
    var other => throw new ArgumentException($"Unknown scheme \"{other}\" — expected \"hmac\" or \"ed25519\""),
};
var prefix = scheme == SigningScheme.Hmac ? "HMAC" : "ED25519";

var secret = scheme == SigningScheme.Hmac
    ? Env("HMAC_SECRET")
    // .env can only carry the PEM with real newlines escaped as literal "\n".
    : Env("ED25519_PRIVATE_KEY_PEM").Replace("\\n", "\n");

try
{
    var response = await new PartnerClient().HandoffAsync(new HandoffOptions
    {
        BaseUrl = Env("API_BASE_URL"),
        Scheme = scheme,
        Secret = secret,
        PartnerId = Env($"{prefix}_PARTNER_SLUG"),
        PartnerUserId = Env($"{prefix}_TEST_PARTNER_USER_ID"),
        PhoneNumber = Env($"{prefix}_TEST_PHONE_NUMBER"),
    });

    Console.WriteLine($"status: {response.Status}");
    if (response.Ok && response.DataAs<HandoffResult>() is { } result)
        Console.WriteLine($"entryUrl: {result.EntryUrl} (expires in {result.ExpiresIn}s)");
    Console.WriteLine("body: " + (response.Json is { } json
        ? JsonSerializer.Serialize(json, new JsonSerializerOptions { WriteIndented = true })
        : response.RawBody));
}
catch (Exception error)
{
    Console.Error.WriteLine($"Request failed: {error}");
    Environment.ExitCode = 1;
}

static string Env(string name) =>
    Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
        ? value
        : throw new InvalidOperationException($"Missing env var {name} — copy .env.example to .env and fill it in");

// Minimal .env loader — walks up from the working directory to the first .env; real env vars win.
static void LoadEnv()
{
    for (var dir = new DirectoryInfo(Directory.GetCurrentDirectory()); dir is not null; dir = dir.Parent)
    {
        var path = Path.Combine(dir.FullName, ".env");
        if (!File.Exists(path)) continue;

        foreach (var line in File.ReadAllLines(path))
        {
            var trimmed = line.Trim();
            var eq = trimmed.IndexOf('=');
            if (trimmed.StartsWith('#') || eq <= 0) continue;

            var key = trimmed[..eq].Trim();
            if (Environment.GetEnvironmentVariable(key) is null)
                Environment.SetEnvironmentVariable(key, trimmed[(eq + 1)..].Trim());
        }
        return;
    }
}
