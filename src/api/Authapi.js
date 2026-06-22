import API from "./axiosConfig";

export const login = (username, password) =>
  API.post("/auth/login", { username, password });

export const signup = (username, password) =>
  API.post("/auth/signup", { username, password });