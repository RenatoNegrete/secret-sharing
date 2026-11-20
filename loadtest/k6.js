// Mirror of the organizer's load test: 200 requests/s for 60 s.
// Each iteration is one create + one read, so 100 iterations/s = 200 rps.
//
//   k6 run loadtest/k6.js
//   PASSPHRASE_RATIO=0.1 k6 run loadtest/k6.js   # 10% of Secrets use a Passphrase
//
// With the default per-IP create limit (10/s) most creates from one machine
// get a fast 429 — that is the real trade-off. To measure raw latency, start
// the stack with RATE_CREATE_PER_SEC=1000 RATE_READ_PER_SEC=1000.
import http from "k6/http";
import { check } from "k6";

const BASE = __ENV.BASE_URL || "http://localhost:8080";
const PP_RATIO = parseFloat(__ENV.PASSPHRASE_RATIO || "0");

export const options = {
  scenarios: {
    load: {
      executor: "constant-arrival-rate",
      rate: 100,
      timeUnit: "1s",
      duration: __ENV.DURATION || "60s",
      preAllocatedVUs: 50,
      maxVUs: 300,
    },
  },
  thresholds: { http_req_duration: ["p(99)<100"] },
  summaryTrendStats: ["avg", "p(50)", "p(90)", "p(95)", "p(99)", "max"],
};

const json = { headers: { "Content-Type": "application/json" } };

export default function () {
  const usePP = Math.random() < PP_RATIO;
  const body = { content: `load-${__VU}-${__ITER}`, ttl_seconds: 60, max_views: 1 };
  if (usePP) body.passphrase = "load-pass";
  const c = http.post(`${BASE}/secrets`, JSON.stringify(body), { ...json, tags: { name: "create" } });
  check(c, { "create 201": (r) => r.status === 201 });
  if (c.status !== 201) return;
  const hdr = usePP ? { "X-Passphrase": "load-pass" } : {};
  const r = http.get(`${BASE}/s/${c.json("id")}`, { headers: hdr, tags: { name: "read" } });
  check(r, { "read 200": (x) => x.status === 200 });
}
