import API from "./axiosConfig";

export const getConnections = () =>
  API.get("/api/connections");

export const getConnectionStats = () =>
  API.get("/api/connections/stats");

export const getConnectionsByState = (state) =>
  API.get(`/api/connections/state/${state}`);

export const getConnectionsByApp = (app) =>
  API.get(`/api/connections/app/${app}`);