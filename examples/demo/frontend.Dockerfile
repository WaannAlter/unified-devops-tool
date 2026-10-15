FROM python@sha256:9901e0a8d75037d8242ed43155cbcb2d1f61be1356383d8054afb59fd50e39c4 AS test
WORKDIR /site
COPY index.html ./
RUN python -c "from pathlib import Path; assert 'Public toolkit demo' in Path('index.html').read_text()"

FROM python@sha256:9901e0a8d75037d8242ed43155cbcb2d1f61be1356383d8054afb59fd50e39c4 AS runtime
WORKDIR /site
COPY --from=test /site/index.html ./
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "http.server", "8080", "--bind", "0.0.0.0"]
