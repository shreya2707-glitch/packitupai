import { interpolateRgb } from "d3-interpolate";
import { scaleLinear } from "d3-scale";
import type { Level } from "./types";

export const LEVELS: Level[] = ["critical", "high", "medium", "low"];

export const LEVEL_COLOR: Record<Level, string> = {
  critical: "#c4162a",
  high: "#e3630f",
  medium: "#b98a00",
  low: "#5f7d9c",
};

/** Continuous colour for a 0-100 risk score, used on graph nodes. */
export const colorForScore = scaleLinear<string>()
  .domain([0, 35, 60, 80, 100])
  .range(["#9aa6b6", LEVEL_COLOR.medium, LEVEL_COLOR.high, LEVEL_COLOR.critical, LEVEL_COLOR.critical])
  .interpolate(interpolateRgb)
  .clamp(true);

export const shortKey = (key: string) => key.replace(/^[^:]+:/, "");
