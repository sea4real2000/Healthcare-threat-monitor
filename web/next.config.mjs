/** @type {import('next').NextConfig} */
const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' },
];

const nextConfig = {
  poweredByHeader: false,
  // The Docker image runs the small standalone server. Vercel and npm start ignore this.
  output: process.env.NEXT_OUTPUT === 'standalone' ? 'standalone' : undefined,
  // Uploads from the console: pictures, spreadsheets and records reports. The limits administrators see are the
  // media.max_bytes and uploads.max_bytes settings, which must stay below this. Vercel caps any request at about 4.5 MB.
  experimental: { serverActions: { bodySizeLimit: '25mb' } },
  // The Windows collector's files are read when an installer is built, so they travel with the server.
  outputFileTracingIncludes: { '/api/collectors/windows/[id]': ['./collectors/windows/*.ps1', './collectors/windows/*.cs'] },
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};

export default nextConfig;
