import API from "./axiosConfig";

export const uploadPcap = (formData) =>
  API.post("/api/packets/analyze", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });

export const getPacketStatus = () =>
  API.get("/api/packets/status");

export const getReport = () =>
  API.get("/api/packets/report");

export const analyzeRaw = (hexData) =>
  API.post("/api/packets/raw", { data: hexData });