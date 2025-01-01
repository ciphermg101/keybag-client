interface RecentActivitiesProps {
  recentActivities: string[];
}

const RecentActivities: React.FC<RecentActivitiesProps> = ({ recentActivities }) => (
  <div>
    <h2>Recent Activities</h2>
    <ul>
      {recentActivities.map((activity, index) => (
        <li key={index}>
          {activity.startsWith("Added password for") ? (
            <span className="activity-highlight">{activity}</span>
          ) : (
            activity
          )}
        </li>
      ))}
    </ul>
  </div>
);

export default RecentActivities;
