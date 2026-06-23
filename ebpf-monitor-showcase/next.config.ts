import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // 为 Docker 生产镜像提供最小运行时产物
  // 详见 https://nextjs.org/docs/app/building-your-application/deploying#docker-image
  output: "standalone",
};

export default nextConfig;
