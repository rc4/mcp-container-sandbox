import { DurableObject } from 'cloudflare:workers';

/** Only fixed webhook code runs here; this container is never exposed to analysis tools. */
export class WebhookGateway extends DurableObject<Env> {
  async post(request: { url: string; headers: Record<string, string>; body: string }): Promise<
    { status: number; body: string } | { error: string }
  > {
    const container = this.ctx.container;
    if (!container) throw new Error('The webhook container binding is not configured');
    if (!container.running) {
      container.start({ image: container.images.webhook!, enableInternet: true });
    }
    await container.setInactivityTimeout(60_000);
    const process = await container.exec(['node', '/opt/webhook.mjs'], {
      stdin: new Blob([JSON.stringify(request)]).stream(),
      signal: AbortSignal.timeout(60_000),
    });
    const output = await process.output();
    if (output.exitCode !== 0) throw new Error('Webhook sender process failed');
    return JSON.parse(new TextDecoder().decode(output.stdout));
  }
}
