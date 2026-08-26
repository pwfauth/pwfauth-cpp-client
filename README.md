# PWF Auth Native C++ Desktop Sample

An English Windows desktop client written in native C++17. It mirrors the same
license flow as the C# and Python samples:

- encrypted license login and HWID binding;
- live heartbeat with server-driven session termination;
- complete license summary, flattened response table, and raw JSON;
- explicit logout that frees the server session.

The PWF Auth site does not publish a C++ package. This sample therefore implements
the documented protocol directly with Windows APIs:

- WinHTTP for HTTPS;
- Windows CNG for SHA-256, AES-256-CBC, HMAC-SHA256, and secure IV generation;
- the Windows cryptography `MachineGuid` for the hardware ID;
- `nlohmann-json`, restored automatically through the included vcpkg manifest.

## Configure

Replace the placeholder near the top of `main.cpp`:

```cpp
constexpr char APP_SECRET[] = "YOUR_64_CHARACTER_APP_SECRET";
```

The program validates that the replacement is a 64-character hexadecimal value
before it contacts the API. It remains in source only because this is an educational
sample; production applications should inject the secret during the build and
obfuscate release binaries.

## Build and run

Open `PWFAuthCpp.slnx` in Visual Studio, select `Debug | x64`, and press `F5`.
The project restores its vcpkg dependency locally during the first build.

The executable is written to:

```text
bin\Debug\PWFAuthCpp.exe
```

The application runs an offline AES/HMAC round-trip self-test before showing the
sign-in window. A real login still requires the application secret and a valid key.
