# Dotnet_JWTLogoutAsync

## Introduction
Never trust anything coming from the client-side they said, but why you are still trusting the client-side to handle your application logout properly and effectively,
when all he did, was delete the stored jwt from the browser local storage.  
If such stored jwt was copied before it is deleted, or it was intercepted in transit,
it can still be used on a different computer or browser, and it will still work perfectly like it was never deleted. 

This package aims to help you handle your logout process seamlessly with just 3 lines of code:  
~> var jwtCheck = new JwtCheck().Login(generatedJwt).GetAwaiter().GetResult(); in your login method  
~> var jwtCheck = new JwtCheck().Logout(httpContext).GetAwaiter().GetResult(); in your logout method  
~> app.UseJWTCheck(); in your program.cs 

N:B => you can check this link: [Dotnet_JWTLogout](https://github.com/masterpiece007/Dotnet_JWTLogout) for the syncronous method equivalent  

## Use Case
- You wish to disable Jwt from authorizing your application before the token expiry time elapse.
- It can be used with your custom Jwt implementation as well as with ASP.NET Identity.

## Support
- .NET Core 6.0 and newer

## Installation
You can clone this repo and reference it in your project.  

Install via .NET CLI

```bash
dotnet add package JWTLogoutAsync.Net --version 1.0.0
```
Install via Package Manager

```bash
Install-Package JWTLogoutAsync.Net -Version 1.0.0
```
## Usage
To enable JWTLogout to listen for requests, use the middleware provided by JWTLogout.  
Add JWTLogout Namespace in `Program.cs`

```c#
using JWTLogoutAsync.Net.Helpers
```
#### Call JWTLogout middleware after app.UseAuthorization() in program.cs;

```c#
...
app.UseAuthentication();
app.UseAuthorization();
app.UseJWTCheck();
...
```

#### Call JwtCheck.LoginAsync() method at the bottom of your Login Function/ActionMethod;

```c#
...
var jwtCheck = new JwtCheck().LoginAsync(generatedJwt).GetAwaiter().GetResult();
...
```

#### Call JwtCheck.Logout() method at the bottom of your Login Function/ActionMethod;

```c#
...
var jwtCheck = new JwtCheck().LogoutAsync(httpContext).GetAwaiter().GetResult();
...
```
## Contribution
Feel like something is missing? Fork the repo and send a PR.

Encountered a bug? Fork the repo and send a PR.

Alternatively, open an issue and we'll get to it as soon as we can.

