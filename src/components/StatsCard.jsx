function StatsCard({ title, value }) {
  return (
    <div className="card shadow">
      <div className="card-body">
        <h5>{title}</h5>
        <h3>{value}</h3>
      </div>
    </div>
  );
}

export default StatsCard;