# ============================================================================
# 1. PARSING - Load and prepare the data
# ============================================================================
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
df = pd.read_csv('C:/Users/gnana/Downloads/sysmon.csv', parse_dates=["Timestamp"])
df = df.sort_values("Timestamp")
E_PROC, E_NET, E_OK, E_FAIL, E_LOGOFF = 1, 3, 4624, 4625, 4634
print(f"Loaded {len(df)} events")
print(f"Date range: {df['Timestamp'].min()} to {df['Timestamp'].max()}")
print(f"Event types: {sorted(df['EventID'].unique())}")
print(f"Users: {sorted(df['User'].unique())}")
print("\nFirst few rows:")
print(df.head())

# ============================================================================
# HEATMAP - User activity by hour
# ============================================================================
plt.figure(figsize=(12, 6))
df['Hour'] = df['Timestamp'].dt.hour
heatmap_data = df.pivot_table(index='User', columns='Hour', values='EventID', aggfunc='count', fill_value=0)
sns.heatmap(heatmap_data, cmap='Reds', annot=True, fmt='.0f')
plt.title('User Activity Heatmap by Hour')
plt.xlabel('Hour of Day')
plt.ylabel('User')
plt.tight_layout()
plt.show()

# ============================================================================
# BOX PLOT - Time intervals between events
# ============================================================================
print("Creating box plot...")
plt.figure(figsize=(10, 6))
interval_data = []
event_labels = []
for event_id in sorted(df['EventID'].unique()):
    event_times = df[df['EventID'] == event_id]['Timestamp'].sort_values()
    if len(event_times) > 1:
        intervals = event_times.diff().dt.total_seconds() / 60  # Convert to minutes
        intervals = intervals.dropna()
        if len(intervals) > 0:
            interval_data.append(intervals)
            event_labels.append(f'Event {event_id}')
if interval_data:
    plt.boxplot(interval_data, labels=event_labels)
    plt.title('Time Intervals Between Events')
    plt.xlabel('Event Type')
    plt.ylabel('Interval (Minutes)')
plt.tight_layout()
plt.show()

# ============================================================================
# SPARKLINES - All users activity over time in single graph
# ============================================================================
plt.figure(figsize=(14, 8))
users = df['User'].unique()
colors = ['blue', 'red', 'green', 'orange', 'purple', 'brown', 'pink', 'gray', 'olive', 'cyan']
for i, user in enumerate(users):
    user_data = df[df['User'] == user].set_index('Timestamp')
    hourly_counts = user_data.resample('h').size()
    color = colors[i % len(colors)]  # Cycle through colors if more users than colors
    plt.plot(hourly_counts.index, hourly_counts.values,
             color=color, linewidth=2, label=f'{user}', marker='o', markersize=3)
plt.title('User Activity Sparklines - All Users Comparison', fontsize=16)
plt.xlabel('Time')
plt.ylabel('Events per Hour')
plt.legend(bbox_to_anchor=(1, 1), loc='upper left')
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.show()

# ============================================================================
# sparklines - user level - event id
# ============================================================================
df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
unique_eventids = sorted(df["EventID"].unique())
eventid_map = {eid: idx for idx, eid in enumerate(unique_eventids)}
df["EventID_mapped"] = df["EventID"].map(eventid_map)
users = df["User"].unique()
for user in users:
    user_df = df[df["User"] == user]
    plt.figure(figsize=(10, 2))  # sparkline style
    plt.plot(user_df["Timestamp"], user_df["EventID_mapped"], linewidth=1, marker="o", markersize=3)
    plt.yticks(range(len(unique_eventids)), unique_eventids, fontsize=6)  # show actual EventIDs on y-axis
    plt.title(f"User: {user}", fontsize=8, loc="left")
    plt.tight_layout()
    plt.show()

# ============================================================================
# QUESTION 1 - Multiple failed login attempts (≥4) followed by a successful login for a specific user within a short timeframe.
# ============================================================================
from datetime import timedelta
for user in df['User'].dropna().unique():
  print(user)
  failure_count = 0
  failure_time = []
  event_login = df[(df["User"]==user) & (df['EventID'].isin([4624,4625]))]
  event_login = event_login.sort_values("Timestamp")
  for _,row in event_login.iterrows():
    if row["EventID"] == 4625:
      failure_count += 1
      failure_time.append(row["Timestamp"])
    elif row["EventID"] == 4624:
      if(failure_count>=4):
          if(row["Timestamp"] - failure_time[0]<=timedelta(days=3)):
            print(failure_time)
            break
      failure_count = 0
      failure_time = []
      
# ============================================================================
# Question 2 - Suspicious process launch: powershell with encoded commands or mimikatz.exe.
# ============================================================================
procs = df[df['EventID'] == 1] #Event process create
pats = [r'mimikatz\.exe', r'powershell.* -EncodedCommand', r'powershell.* -e', r'powershell.* -enc']
mask = ( procs['Image'].str.contains(pats[0], case=False, na=False) |
         procs['CommandLine'].str.contains('|'.join(pats[1:]), case=False, na=False))
sus = procs[mask].drop_duplicates()
if not sus.empty:
    print(sus[['User', 'Image']])
else:
    print("No suspicious process launches found.")

# ============================================================================
# Question 3 - Network connection to rare/malicious IPs multiple times from the same user.
# ============================================================================
network_connections = df[df['EventType'] == 'NetworkConnect']
connection_counts = network_connections.groupby(['User', 'DestinationIp']).size().reset_index(name='Count')
suspicious_connections = connection_counts[connection_counts['Count'] > 1]
if not suspicious_connections.empty:
    for index, row in suspicious_connections.iterrows():
      print(row)
else:
    print("No users found making multiple connections to the same IP.")

# ============================================================================
# Question 4 - Short login-logout sessions (<10 mins) for some users.
# ============================================================================
user_sessions = {}
for index, row in df.iterrows():
    user = row['User']
    event_type = row['EventType']
    timestamp = row['Timestamp']
    if user not in user_sessions:
        user_sessions[user] = {'login_time': None}
    if event_type == 'LoginSuccess':
        user_sessions[user]['login_time'] = timestamp
    elif event_type == 'Logout':
        if user_sessions[user]['login_time']:
            session_duration = timestamp - user_sessions[user]['login_time']
            if session_duration.total_seconds() / 60 < 10:
                print(f"User '{user}' had a short session of {session_duration}")

        user_sessions[user]['login_time'] = None

# Also create a summary of total activity per user //optional - to see last - for spark lines
print("\nUser Activity Summary:")
user_activity = df['User'].value_counts().sort_values(ascending=False)
for user, count in user_activity.items():
    print(f"  {user}: {count} total events")
print(f"\nMost active user: {user_activity.index[0]} ({user_activity.iloc[0]} events)")
print(f"Least active user: {user_activity.index[-1]} ({user_activity.iloc[-1]} events)")
