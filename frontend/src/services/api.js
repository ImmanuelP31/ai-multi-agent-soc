import axios from "axios";
 
// Empty baseURL = relative to current origin.
// In dev, Vite proxy forwards /alerts/* → http://127.0.0.1:8000
// In production, set VITE_API_URL in your .env file.
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "",
});
 
export default api;
 