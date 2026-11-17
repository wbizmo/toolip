# Distribution image source only. No release image may be published or
# described as signed until the separately trusted release workflow is
# approved and actual provenance/signatures are verified.
#
# Pass fully qualified immutable image@sha256 references for both ARGs.
# This file deliberately has no mutable or guessed base-image default.
ARG BUILDER_IMAGE
ARG RUNTIME_IMAGE

FROM ${BUILDER_IMAGE} AS builder
WORKDIR /toolip
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json tsconfig.quality.json ./
COPY src ./src
RUN npm run build
RUN npm prune --omit=dev --ignore-scripts --no-audit --no-fund
# The trusted CLI is exposed as an ordinary executable for CI scripts.
# Never use npm install or project-provided shell hooks at container startup.
RUN printf '#!/bin/sh\nexec node /app/dist/src/index.js "$@"\n' > /toolip/toolip && chmod 0755 /toolip/toolip

FROM ${RUNTIME_IMAGE} AS runtime
ARG SOURCE_GIT_SHA
LABEL org.opencontainers.image.source="https://github.com/wbizmo/toolip" \
      org.opencontainers.image.vendor="Zivora Labs" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="${SOURCE_GIT_SHA}"
WORKDIR /app
COPY --from=builder --chown=65532:65532 /toolip/package.json ./package.json
COPY --from=builder --chown=65532:65532 /toolip/node_modules ./node_modules
COPY --from=builder --chown=65532:65532 /toolip/dist ./dist
COPY --from=builder --chown=0:0 /toolip/toolip /usr/local/bin/toolip
USER 65532:65532
ENV NODE_ENV=production
ENTRYPOINT ["node", "/app/dist/src/index.js"]
CMD ["--help"]
