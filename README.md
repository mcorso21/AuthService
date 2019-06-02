# Auth Services
## Using this Library
---
### JSON Web Token (JWT) Service
1. Ensure JWTService.UpdateSecretKey is pulling the SecretKey from the correct location, it defaults to looking in App.config:
    ```cs 
    secretKey = ConfigurationManager.AppSettings.Get("SecretKey");
2. Create an instance of JWTService
    ```cs
    JWTService jwtService = new JWTService();
3. Generate a JWT
    ```cs
    string token = jwtService.GenerateToken(new Claim[] { new Claim(ClaimTypes.Email, "name@gmail.com") });
4. Validate a JWT
    ```cs 
    bool isValid = jwtService.IsTokenValid(token);
5. Get the claims in a JWT
    ```cs
    // Get the tokens
    var jwtClaims = jwtService.GetTokenClaims(token);
    // Get a specific value
    string email = "";
    email = jwtClaims.Where(x => x.Type.Equals(ClaimTypes.Email.ToString())).FirstOrDefault().Value;
    // Iterate through the tokens
    long expiration= 0;
    foreach(Claim claim in jwtClaims)
    {
        if(claim.Type.Equals("exp"))
            expiration = long.Parse(claim.Value);
        else if (claim.Type.Equals(ClaimTypes.Email.ToString()))
            email = claim.Value;
    }