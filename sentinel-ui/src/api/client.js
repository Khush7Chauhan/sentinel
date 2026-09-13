import { DEMO_DATA } from "../data/mockData";

const API_BASE_URL = "http://127.0.0.1:8000";

export async function runSecurityScan(targetDir, fallbackDataset = DEMO_DATA) {
  try {
    const response = await fetch(
      `${API_BASE_URL}/api/scan?target_dir=${encodeURIComponent(targetDir)}`,
      { method: "POST" }
    );
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: Failed to execute security scan`);
    }
    return await response.json();
  } catch (error) {
    console.warn("Backend offline or unreachable, falling back to local dataset:", error);
    return fallbackDataset;
  }
}