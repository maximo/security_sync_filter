using security_sync_filter;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Configuration;
using System.Data.Entity;
using System.Data.Entity.Core.EntityClient;
using System.DirectoryServices;
using System.Linq;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Utils;

namespace Sync_Filter
{
    public partial class Service : ServiceBase
    {
        EntityConnectionStringBuilder entity = new EntityConnectionStringBuilder();
        private ManualResetEvent shutdownEvent;
        private Thread syncThread;
        private int delay;
        private bool stopping;
        private Regex regex;
        private Hashtable groups;
        internal AppEventLog logger;

        public Service()
        {
            InitializeComponent();
            this.stopping = false;
            this.logger = new AppEventLog(this.ServiceName, "Application");
            this.shutdownEvent = new ManualResetEvent(false);
            this.groups = new Hashtable();
            this.regex = new Regex(@"CN=([^,]+),.*$", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);
        }

        protected override void OnStart(string[] args)
        {
            string customer = "";
            string licenses = "";

            // License check
            DateTime expiration = new DateTime(2019, 1 /* month */, 1/* day */, 12, 0, 0);
            if (DateTime.Compare(DateTime.Now, expiration) >= 0)
            {
                if (customer == null)
                {
                    logger.LogError("This trial version of Security Sync Filter is expired. Please contact www.lync-solutions.com to purchase a license.");
                }
                else
                {
                    logger.LogError("This Security Sync Filter license has expired. Please contact www.lync-solutions.com to renew your license");
                }
                this.Stop();
                return;
            }

            // Reead settings from configuration file.
            string install_path, logging = "normal";
            try
            {
                entity.Provider = ConfigurationManager.ConnectionStrings["db"].ProviderName;
                entity.ProviderConnectionString = ConfigurationManager.ConnectionStrings["db"].ConnectionString;
                entity.Metadata = @"res://*/ActiveDirectoryModel.csdl|res://*/ActiveDirectoryModel.ssdl|res://*/ActiveDirectoryModel.msl";

                // Refresh interval.
                delay = Convert.ToInt32(ConfigurationManager.AppSettings["interval"]);

                // Logging level.
                if (ConfigurationManager.AppSettings["logLevel"] != "")
                {
                    logging = ConfigurationManager.AppSettings["logLevel"];
                }

                install_path = ConfigurationManager.AppSettings["path"];
            }
            catch(Exception ex)
            {
                logger.LogError("Failed to read configuration.\n\nError: " + ex.Message);
                this.Stop();
                return;
            }

            // license information.
            string copyright = "Copyright (c) 2010-2016 MB Corporation. All rights reserved. Decompilation or reverse engineering is strictly prohibited.";
            if (!string.IsNullOrEmpty(customer))
            {
                copyright += "\n\nThe Security Sync Filter Enterprise Edition for Lync Server 2013 is expressedly licensed to " +
                                customer + " for use on " + licenses + " servers.";
            }
            copyright += "\nTo purchase licenses, please contact www.lync-solutions.com.";

            logger.LogInfo(copyright + "\n\nService: " + this.ServiceName +
                                    "\nRefresh interval: " + this.delay + " day(s)" +
                                    "\nLogging level: " + logging);

            System.Diagnostics.Trace.WriteLine("\n" + copyright + 
                                    "\n\nStarting: " + this.ServiceName + 
                                    "\nRefresh interval: " + this.delay + " day(s)" +
                                    "\nLogging level: " + logging);

            syncThread = new Thread(new ThreadStart(SyncManager));
            syncThread.IsBackground = true;
            syncThread.Start();
            System.Diagnostics.Trace.WriteLine("\nStarted: " + this.ServiceName);
        }

        protected override void OnStop()
        {
            System.Diagnostics.Trace.WriteLine("\nStopping: " + this.ServiceName);
            this.stopping = true;
            this.shutdownEvent.Set();
        }

        private async void SyncManager()
        {
            try
            {
                int wait_time = delay * 3600000; // convert to days (unit of measurement).
                DateTime start, stop;
                TimeSpan duration;

                while (false == this.stopping)
                {
                    start = DateTime.Now;
                    System.Diagnostics.Trace.WriteLine("\n\nSync: " + start.ToString());
                    await Find();
                    stop = DateTime.Now;
                    duration = stop - start;
                    System.Diagnostics.Trace.WriteLine("Total Time: " + duration.ToString());
                    await CleanUp();
                    this.shutdownEvent.WaitOne(wait_time);
                } 
            }
            catch(Exception ex)
            {
                string message = this.ServiceName + " is unresponsive. Restart this service.\n";
                logger.LogError(message);
                System.Diagnostics.Trace.WriteLine(message + ex.Message + (ex.InnerException == null ? "" : ex.InnerException.Message));
            }
            System.Diagnostics.Trace.WriteLine("\nStopped: " + this.ServiceName);
        }

        private async Task<bool> CleanUp()
        {
            bool bResult = true;

            System.Diagnostics.Trace.WriteLine("\nCleanup SecurityFilterManager database: " + this.ServiceName);

            DateTime staleTime = DateTime.Now.AddDays(delay * (-1)); // Any data longer than (delay) days is considered stale.
            const string SQL_DELETE = "DELETE FROM {0} WHERE TIMESTAMP < {1}";

            foreach (string table in new List<string>(new string[] {"FederationGroupMemberships","FederationGroups", "ADUsers"}))
            {
                using(var db = new SecurityFilterManagerEntities(entity.ToString()))
                {
                    string sqlcmd = string.Format(SQL_DELETE, table, staleTime.ToShortDateString());
                    System.Diagnostics.Trace.WriteLine(sqlcmd);
                    Task<int> task = db.Database.ExecuteSqlCommandAsync(sqlcmd);
                    int result = await task;
                    if (true == this.stopping)
                    {
                        bResult = false;
                        break;
                    }
                }
            }

            return bResult;
        }

        private async Task<bool> Find()
        {
            bool bResult = true;
            try
            {
                using (DirectoryEntry deContainer = new DirectoryEntry())
                {
                    using (DirectorySearcher srchUsers = new DirectorySearcher(deContainer))
                    {
                        // Search recursively.
                        srchUsers.SearchScope = SearchScope.Subtree;
                        srchUsers.PageSize = 1000;
                        // Use for performance optimization.
                        srchUsers.Asynchronous = true;
                        // Search all Lync/SfB enabled users.
                        srchUsers.Filter = ("(&(objectCategory=person)(objectClass=user)(msRTCSIP-UserEnabled=*))");
                        // Only retrieve the following properties to speed up performance.
                        srchUsers.PropertiesToLoad.Add("displayName");
                        srchUsers.PropertiesToLoad.Add("msRTCSIP-PrimaryUserAddress");

                        List<Task<bool>> tasks = new List<Task<bool>>();

                        // Parallel 1000 users at a time so the system doesn't run out of memory.
                        int i = 0;

                        // Find all users under an Active Directory container.
                        foreach (SearchResult _user in srchUsers.FindAll())
                        {
                            // speed up overall time by running these operations in parallel.
                            tasks.Add(User(_user.GetDirectoryEntry()));
                            // Service is being stopped.
                            if (true == this.stopping) break;

                            // increment counter
                            i++;

                            if(i == 1000)
                            {
                                // Wait for all operations to complete before returning from this function.
                                await Task.WhenAll(tasks);
                                tasks.Clear();
                                // reset counter
                                i = 0;
                            }
                        }
                    }
                }
            }
            catch(Exception ex)
            {
                System.Diagnostics.Trace.WriteLine("Find(): " + ex.Message + 
                                        (ex.InnerException == null ? "" : ex.InnerException.Message) + 
                                        "\n" + ex.StackTrace);
                bResult = false;
            }

            return bResult;
        }

        //private async Task<bool> User(String userDN)
        private async Task<bool> User(DirectoryEntry user_entry)
        {
            bool bStatus = true;

            String displayname = Convert.ToString(user_entry.Properties["displayName"].Value);
            String sipuri = Convert.ToString(user_entry.Properties["msRTCSIP-PrimaryUserAddress"].Value);
            // strip out "sip:" tag in front of the SIP URI.
            sipuri = sipuri.Substring("sip:".Length);

            DateTime start = DateTime.Now;

            using (var db = new SecurityFilterManagerEntities(entity.ToString()))
            {
                using (var dbTransact = db.Database.BeginTransaction())
                {
                    ADUser _user = null;
                    try
                    {
                        // check whether user already exists in database.
                        Task<ADUser> user_task = db.ADUsers.Where(c => c.Name == sipuri).FirstOrDefaultAsync();
                        _user = await user_task;
                        if (_user == null)
                        {
                            // create new user in database.
                            _user = new ADUser() { Name = sipuri, TimeStamp = DateTime.Now };
                            db.ADUsers.Add(_user);
                        }
                        else
                        {
                            _user.TimeStamp = DateTime.Now;
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Trace.WriteLine("user [" + sipuri + "] exception: " + ex.Message + "\t" + ex.StackTrace);
                    }

                    // retrieve Active Directory groups user is a member of.
                    foreach (var group in user_entry.Properties["MemberOf"])
                    {
                        Match m = regex.Match(group.ToString());
                        string ad_group = m.Groups[1].Value;

                        int _groupId = 0;
                        // Service is being stopped.
                        if (true == this.stopping) break;
                        try
                        {
                            // check whether group name entry has already been updated and cached.
                            if (groups.ContainsKey(ad_group))
                            {
                                _groupId = (int)groups[ad_group];
                                // break out of loop.
                                break;
                            }
                            else
                            {
                                // check whether group already exists in database.
                                FederationGroup _group = db.FederationGroups.Where(c => c.Name == ad_group).FirstOrDefault();
                                if (_group == null)
                                {
                                    // create new group in database.
                                    _group = new FederationGroup() { Name = ad_group, TimeStamp = DateTime.Now };
                                    db.FederationGroups.Add(_group);
                                    System.Diagnostics.Trace.WriteLine("Add group: " + ad_group);
                                }
                                else
                                {
                                    _group.TimeStamp = DateTime.Now;
                                }

                                try // Add group name to hashtable.
                                {
                                    groups.Add(ad_group, _group.Id);
                                }
                                catch { } // do nothing as group has already been added to hash table by another background thread.
                                _groupId = _group.Id;
                            }
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Trace.WriteLine("group [" + ad_group + "] exception: " + 
                                                    ex.Message + (ex.InnerException == null ? "" : ex.InnerException.Message) +
                                                    "\n" + ex.StackTrace);
                        }

                        // Service is being stopped.
                        if (true == this.stopping) break;
                        try
                        {
                            // check whether group membership already exists in database.
                            FederationGroupMembership _membership = db.FederationGroupMemberships.Where(c =>
                                                c.FederationGroupMembershipItem_ADUser == _user.Id &&
                                                c.FederationGroupMembershipItem_FederationGroup == _groupId
                                            ).FirstOrDefault();
                            if (_membership == null)
                            {
                                // create new membership association in database.
                                _membership = new FederationGroupMembership()
                                {
                                    FederationGroupMembershipItem_ADUser = _user.Id,
                                    FederationGroupMembershipItem_FederationGroup = _groupId,
                                    TimeStamp = DateTime.Now
                                };
                                db.FederationGroupMemberships.Add(_membership);
                            }
                            else
                            {
                                _membership.TimeStamp = DateTime.Now;
                            }
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Trace.WriteLine("membership [" + sipuri + ", " + ad_group + "] exception: " + 
                                                    ex.Message + (ex.InnerException == null ? "" : ex.InnerException.Message) +
                                                    "\n" + ex.StackTrace);
                        }
                    }
                    db.SaveChanges();
                    dbTransact.Commit();
                }
            }

            DateTime stop = DateTime.Now;
            TimeSpan duration = stop - start;
            System.Diagnostics.Trace.WriteLine(sipuri +" [" + displayname + "]: " + duration.Milliseconds.ToString() + " milliseconds");
            return bStatus;
        }
    }
}
