using System.Diagnostics;

namespace Utils
{
    #region EventLogHelper
    public class AppEventLog
    {
        public static void RegisterEventSource (string eventLogSource, string eventLogTarget)
        {
            if (!EventLog.SourceExists (eventLogSource)) {
                EventLog.CreateEventSource (eventLogSource, eventLogTarget);
            }
        }

        public static void UnregisterEventSource (string eventLogSource)
        {
            if (EventLog.SourceExists (eventLogSource)) {
                EventLog.DeleteEventSource (eventLogSource);
            }
        }

        public AppEventLog (string eventLogSource, string eventLogTarget)
        {
            if (!EventLog.SourceExists (eventLogSource)) {
                EventLog.CreateEventSource (eventLogSource, eventLogTarget);
            }

            this.eventLog = new EventLog (eventLogTarget);
            this.eventLog.Source = eventLogSource;
        }

        public void Log (EventLogEntryType type, string message)
        {
            if (eventLog != null) {
                eventLog.WriteEntry (message, type);
            }
        }

        public void LogInfo (string message)
        {
            Log (EventLogEntryType.Information, message);
        }

        public void LogError (string message)
        {
            Log (EventLogEntryType.Error, message);
        }

        public void LogWarning (string message)
        {
            Log (EventLogEntryType.Warning, message);
        }

        EventLog eventLog;
    };
    #endregion
}
