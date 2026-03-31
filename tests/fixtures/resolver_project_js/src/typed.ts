import { sanitize } from "./utils/helper";
import type { Request } from "express";

export function handle(req: Request): string {
    return sanitize(req.body);
}
