import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def read_anomaly_data(file_name):
    return pd.read_csv(file_name)

def plot_anomaly_timeline(df):
    plt.figure(figsize=(10, 6))
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    
    # Assuming 'Anomaly' is a binary indicator (1 for anomaly, 0 for normal)
    sns.lineplot(data=df, x='Timestamp', y='Anomaly')
    plt.title('Timeline of Network Traffic Anomalies')
    plt.xlabel('Timestamp')
    plt.ylabel('Anomaly Indicator')
    plt.show()


def plot_protocol_distribution(df):
    protocol_counts = df['Protocol'].value_counts()
    plt.figure(figsize=(10, 6))
    sns.barplot(x=protocol_counts.index, y=protocol_counts.values)
    plt.title('Protocol Distribution in Anomalous Traffic')
    plt.xlabel('Protocol')
    plt.ylabel('Count')
    plt.show()

def plot_ip_frequency(df):
    ip_counts = df['Source_IP'].value_counts().head(10)  # Top 10 source IPs
    plt.figure(figsize=(12, 6))
    sns.barplot(x=ip_counts.index, y=ip_counts.values)
    plt.title('Top Source IPs in Anomalous Traffic')
    plt.xlabel('Source IP Address')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.show()

def main():
    anomaly_file = 'anomalies.csv'
    df = read_anomaly_data(anomaly_file)

    plot_anomaly_timeline(df)  # Corrected call with only one argument

    plot_protocol_distribution(df)
    plot_ip_frequency(df)

if __name__ == "__main__":
    main()