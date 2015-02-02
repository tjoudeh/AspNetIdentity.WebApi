using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace AspNetIdentity.WebApi.Validators
{
    public class MyCustomPasswordValidator : PasswordValidator
    {

        public override async Task<IdentityResult> ValidateAsync(string password)
        {

            IdentityResult result = await base.ValidateAsync(password);

            if (password.Contains("abcdef") || password.Contains("123456"))
            {
                var errors = result.Errors.ToList();
                errors.Add("Password can not contain sequence of chars");
                result = new IdentityResult(errors);
            }

            return result;
        }

    }
}