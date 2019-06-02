using System;
using System.Security.Claims;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Configuration;
using System.Text;
using System.Linq;
using NLog;
using System.Threading;

namespace AuthService.Services
{
    public class JWTService
    {
        #region Members
        public int ExpirationInMinutes { get; set; } = 1;        // 7 days
        public string SecurityAlgorithm { get; } = SecurityAlgorithms.HmacSha256Signature;
        private string SecretKey;
        private SymmetricSecurityKey SymSecKey;
        protected Logger logger = LogManager.GetCurrentClassLogger();
        #endregion Members

        #region Constructors
        public JWTService(Logger customLogger = null)
        {
            try
            {
                this.UpdateSecretKey();
                // Set NLog logger to custom logger if provided
                if (customLogger != null)
                    this.logger = customLogger;
                logger.Debug($"Successfully created a new instance of JWTService.");
            }
            catch (Exception ex)
            {
                logger.Error($"Failed to create instance of JWTService.\n{ex.Message}\n{ex.StackTrace}");
                throw new Exception($"Failed to create instance of JWTService.", ex);
            }
        }
        #endregion Constructors

        #region Private Functions
        private TokenValidationParameters GetTokenValidationParameters()
        {
            TokenValidationParameters tvp = null;

            try
            {
                tvp = new TokenValidationParameters()
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    IssuerSigningKey = SymSecKey
                };
            }
            catch (Exception ex)
            {
                logger.Error($"Failed to get TokenValidationParameters.\n{ex.Message}\n{ex.StackTrace}");
                throw new Exception($"Failed to get TokenValidationParameters.", ex);
            }
            logger.Debug($"Successfully obtained TokenValidationParameters.");
            return tvp;
        }
        #endregion Private Functions

        #region Public Functions
        public bool UpdateSecretKey()
        {
            string secretKey = "";
            try
            {
                // Updates SecretKey to a value set in App.config
                secretKey = ConfigurationManager.AppSettings.Get("SecretKey");
            }
            catch (Exception ex)
            {
                logger.Error($"Failed to update the secret key.\n{ex.Message}\n{ex.StackTrace}");
                throw new Exception($"Failed to update the secret key.", ex);
            }

            // Check if key is null or empty
            if (string.IsNullOrEmpty(secretKey))
            {
                logger.Error($"Failed to update the secret key, Secret Key is null or empty.");
                throw new ArgumentException($"Secret key is null or empty.");
            }

            // If key is not Base64, convert it
            try
            {
                Convert.FromBase64String(secretKey);
            }
            catch (Exception)
            {
                SecretKey = Convert.ToBase64String(Encoding.UTF8.GetBytes(secretKey));
            }

            // Update the SymmetricSecurityKey using the new Secret Key
            try
            {
                SymSecKey = new SymmetricSecurityKey(Convert.FromBase64String(SecretKey));
            }
            catch (Exception ex)
            {
                logger.Error($"Failed to generate SymmetricSecurityKey.\n{ex.Message}\n{ex.StackTrace}");
                throw new Exception($"Failed to generate SymmetricSecurityKey.", ex);
            }
            logger.Debug($"Successfully updated the Secret Key.");
            return true;
        }
        public string GenerateToken(Claim[] claims)
        {
            if (claims == null || claims.Length < 1)
            {
                logger.Error($"Failed to generate token, no claims provided.");
                throw new ArgumentException("Failed to generate token, no claims provided.");
            }

            string token;

            try
            {
                SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    Expires = DateTime.UtcNow.AddMinutes(Convert.ToInt32(ExpirationInMinutes)),
                    SigningCredentials = new SigningCredentials(SymSecKey, SecurityAlgorithm)
                };

                JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
                SecurityToken securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
                token = jwtSecurityTokenHandler.WriteToken(securityToken);
            }
            catch (Exception ex)
            {
                logger.Error($"Failed to generate token.\n{ex.Message}\n{ex.StackTrace}");
                throw new Exception($"Failed to generate token.", ex);
            }
            logger.Info($"Successfully generated JWT.");
            return token;
        }

        public bool IsTokenValid(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                logger.Error($"Provided token is null or empty.");
                throw new ArgumentException("Provided token is null or empty.");
            }

            try
            {
                TokenValidationParameters tokenValidationParameters = GetTokenValidationParameters();
                JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
                ClaimsPrincipal tokenValid = jwtSecurityTokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);

                logger.Debug($"Successfully validated token.");
                return true;
            }
            catch (Exception)
            {
                logger.Debug($"Failed to validate token.");
                return false;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <returns>
        ///     Claim.Types
        ///         nbf (Not Before):   Claim starting time
        ///             ToString() example: "nbf: 1559442926"
        ///         exp (Expiration):   Claim expiration time
        ///             ToString() example: "exp: 1559442986"
        ///         iat (Issued At):    Claim issue time
        ///             ToString() example: "iat: 1559442926"
        ///         name:               
        ///             ToString() example: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name: name"
        ///         email:
        ///             ToString() example: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress: name@gmail.com"
        /// </returns>
        public IEnumerable<Claim> GetTokenClaims(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                logger.Error($"Failed to get token claims, token is null or empty.");
                throw new ArgumentException("Failed to get token claims, token is null or empty.");
            }

            try
            {
                TokenValidationParameters tokenValidationParameters = GetTokenValidationParameters();
                JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
                ClaimsPrincipal tokenValid = jwtSecurityTokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);
                logger.Debug($"Successfully obtained token's claims.");
                return tokenValid.Claims;
            }
            catch (Exception ex)
            {
                logger.Error($"Failed to get token's claims.\n{ex.Message}\n{ex.StackTrace}");
                throw new Exception($"Failed to get token's claims.\n{ex.Message}\n{ex.StackTrace}");
            }
        }
        #endregion Public Functions
    }
}