import * as net from 'net';
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { AppModule } from '../../src/app.module';
import { RequestFramingMiddleware } from '../../src/common/middleware/request-framing.middleware';

function sendRawHttp(port: number, rawPayload: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port }, () => {
      socket.write(rawPayload);
    });
    let response = '';
    socket.setTimeout(2000, () => {
      socket.destroy();
      resolve(response);
    });
    socket.on('data', (chunk) => {
      response += chunk.toString('utf8');
      if (response.includes('\r\n\r\n')) socket.end();
    });
    socket.on('end', () => resolve(response));
    socket.on('error', reject);
  });
}

describe('HTTP Request Smuggling Regression (#436)', () => {
  let app: INestApplication;
  let port: number;

  beforeAll(async () => {
    const mod = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = mod.createNestApplication();
    app.use((req: any, res: any, next: any) => new RequestFramingMiddleware().use(req, res, next));
    await app.listen(0);
    port = app.getHttpServer().address().port;
  });

  afterAll(async () => {
    await app.close();
  });

  it('rejects conflicting Content-Length and Transfer-Encoding (CL.TE) with 400', async () => {
    const raw =
      'POST /api/v1/health HTTP/1.1\r\n' +
      'Host: localhost\r\n' +
      'Content-Length: 4\r\n' +
      'Transfer-Encoding: chunked\r\n' +
      'Connection: close\r\n\r\n' +
      '0\r\n\r\n';
    const res = await sendRawHttp(port, raw);
    expect(res).toMatch(/^HTTP\/1\.1 400 /);
  });

  it('rejects duplicate Content-Length headers with 400', async () => {
    const raw =
      'POST /api/v1/health HTTP/1.1\r\n' +
      'Host: localhost\r\n' +
      'Content-Length: 5\r\n' +
      'Content-Length: 10\r\n' +
      'Connection: close\r\n\r\n' +
      'hello';
    const res = await sendRawHttp(port, raw);
    expect(res).toMatch(/^HTTP\/1\.1 400 /);
  });

  it('rejects obfuscated Transfer-Encoding (TE.TE) with 400', async () => {
    const raw =
      'POST /api/v1/health HTTP/1.1\r\n' +
      'Host: localhost\r\n' +
      'Transfer-Encoding: chunked, identity\r\n' +
      'Connection: close\r\n\r\n' +
      '0\r\n\r\n';
    const res = await sendRawHttp(port, raw);
    expect(res).toMatch(/^HTTP\/1\.1 400 /);
  });

  it('rejects malformed chunked body framing with 400', async () => {
    const raw =
      'POST /api/v1/health HTTP/1.1\r\n' +
      'Host: localhost\r\n' +
      'Transfer-Encoding: chunked\r\n' +
      'Connection: close\r\n\r\n' +
      'ZZZ\r\ninvalid\r\n0\r\n\r\n';
    const res = await sendRawHttp(port, raw);
    expect(res).toMatch(/^HTTP\/1\.1 400 /);
  });

  it('allows legitimate chunked streamed requests where intended', async () => {
    const body = JSON.stringify({ ping: true });
    const hexLen = Buffer.byteLength(body).toString(16);
    const raw =
      'POST /api/v1/health HTTP/1.1\r\n' +
      'Host: localhost\r\n' +
      'Content-Type: application/json\r\n' +
      'Transfer-Encoding: chunked\r\n' +
      'Connection: close\r\n\r\n' +
      `${hexLen}\r\n${body}\r\n0\r\n\r\n`;
    const res = await sendRawHttp(port, raw);
    // Reaches router (not rejected as 400 framing error)
    expect(res).not.toMatch(/^HTTP\/1\.1 400 /);
  });
});