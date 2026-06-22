import API from "./axiosConfig";

export const getRules = () => API.get("/api/rules");

export const blockIp = (ip) => API.post("/api/rules/ip", { ip });
export const unblockIp = (ip) => API.delete(`/api/rules/ip/${ip}`);
export const checkIp = (ip) => API.get(`/api/rules/ip/${ip}/check`);

export const blockApp = (app) => API.post("/api/rules/app", { app });
export const unblockApp = (app) => API.delete(`/api/rules/app/${app}`);

export const blockDomain = (domain) => API.post("/api/rules/domain", { domain });
export const unblockDomain = (domain) => API.delete("/api/rules/domain", { data: { domain } });

export const blockPort = (port) => API.post("/api/rules/port", { port: Number(port) });
export const unblockPort = (port) => API.delete(`/api/rules/port/${port}`);