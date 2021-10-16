using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices;
namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {

            PrincipalContext l_context;
            UserPrincipal l_user;
            string ourUser;
            try
            {

                System.IO.StreamReader file = new System.IO.StreamReader(@"users_names.txt");
                string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

                while ((ourUser = file.ReadLine()) != null)
                {
                    l_context = new PrincipalContext(ContextType.Domain);
                    l_user = UserPrincipal.FindByIdentity(l_context, IdentityType.SamAccountName, ourUser);
                    if (l_user.HomeDirectory != null)
                    {
                        Console.WriteLine(l_user.DisplayName + " " + l_user.EmailAddress);
                    }
                }
            }
            catch (IOException e)
            {
                Console.WriteLine("The file could not be read:");
                Console.WriteLine(e.Message);
            }
        }
    }
}