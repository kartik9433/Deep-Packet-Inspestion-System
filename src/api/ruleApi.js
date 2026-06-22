import API from "./axiosConfig";

export const getRules = () =>
  API.get("/api/rules");

export const blockIp = (ip) =>
  API.post("/api/rules/ip", { ip });

export const blockDomain = (domain) =>
  API.post("/api/rules/domain", { domain });

export const blockPort = (port) =>
  API.post("/api/rules/port", { port });