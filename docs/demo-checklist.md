# SecureMailScope Demo Checklist

## Pre-Demo Preparation
- [ ] Environment variables configured across services (`frontend`, `gateway`, `analysis`)
- [ ] Database migrations applied and mock dataset seeded
- [ ] Gateway service running and health endpoints passing
- [ ] Analysis engine active and accepting payload requests
- [ ] Frontend dashboard accessible and connected to gateway

## Demo Execution Flow
1. [ ] Demonstrate dashboard overview and metrics
2. [ ] Submit sample email / network traffic payload
3. [ ] Trace request flow through Gateway to Analysis Engine
4. [ ] Verify results parsing and rendering in the UI

## Post-Demo Teardown
- [ ] Clear temporary session data and cache
- [ ] Stop background worker processes
