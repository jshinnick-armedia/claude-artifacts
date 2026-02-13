# 🧐 UNBIASED DESIGN REVIEW REQUEST

Ready Room is a Star Trek LCARS-themed collaboration portal built with Next.js 15 and React 19. The project follows documented architectural patterns and uses a custom coastal theme. Provide a balanced assessment of the application's design, usability, and adherence to our coding guidelines.

## Review Objectives

1. Evaluate architecture and design pattern implementation
2. Assess accessibility (WCAG 2.1/2.2 AA) and responsive design
3. Review performance and real-time interaction quality
4. Examine documentation usability and consistency with CONTRIBUTING.md and docs
5. Offer clear recommendations for improvement

## Current Tech Stack (June 2025)

- **Framework**: Next.js 15.2.3 with React 19 Server Components
- **Language**: TypeScript 5.8.2 (strict mode)
- **Styling**: Tailwind CSS 4.1.7 with coastal theme
- **UI Components**: Catalyst UI Kit and custom LCARS components
- **API**: tRPC 11 with WebSocket subscriptions
- **Database**: PostgreSQL 17 with Prisma 6.5
- **Auth**: NextAuth.js v5 (credentials provider)
- **Monitoring**: Sentry 9.24.0
- **Testing**: Vitest and Playwright suites

## Response Format

### 1. Executive Summary
- Concise overview of strengths and weaknesses
- Highlight major architectural or design concerns

### 2. Heuristic Evaluation
Fill out the following table:

| Heuristic | Score (1–5) | Key Observations | Representative Component | Recommendations |
| --- | --- | --- | --- | --- |
| Visibility of system status | | | | |
| Match between system & real world | | | | |
| User control and freedom | | | | |
| Consistency and standards | | | | |
| Error prevention | | | | |
| Recognition rather than recall | | | | |
| Flexibility and efficiency of use | | | | |
| Aesthetic and minimalist design | | | | |
| Help users recover from errors | | | | |
| Help and documentation | | | | |

### 3. Accessibility Audit
- Note compliance level for key components
- Identify areas that fall short of WCAG 2.1/2.2 AA

### 4. Architecture & Pattern Review
- Assess service layer usage, repository pattern adherence, and component modularity
- Comment on real-time features and performance considerations

### 5. Documentation & Usability
- Evaluate how well docs support new contributors
- Call out outdated or missing information

### 6. Recommendations
- Prioritize critical issues
- List enhancements and future ideas

## Review Guidelines

- Be objective and avoid promotional language
- Reference specific files when possible (`src/path/file.ts:123`)
- Balance positives with areas needing work
- Keep suggestions aligned with established project patterns
