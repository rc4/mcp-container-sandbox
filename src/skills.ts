import { type McpServer, ProtocolError } from '@modelcontextprotocol/server';
import { z } from 'zod';
import triageAgents from '../skills/sample-triage/agents/openai.yaml';
import triage from '../skills/sample-triage/SKILL.md';
import sinkholeAgents from '../skills/sinkhole-analysis/agents/openai.yaml';
import sinkhole from '../skills/sinkhole-analysis/SKILL.md';

export function registerSkills(server: McpServer): void {
  server.server.registerCapabilities({ extensions: { 'io.modelcontextprotocol/skills': {} } });
  const skills = [[triage, triageAgents], [sinkhole, sinkholeAgents]].map(([text, agents]) => {
    // These maintained skills have exactly two plain-string frontmatter fields.
    const match = /^---\nname: ([^\n]+)\ndescription: ([^\n]+)\n---\n/.exec(text!)!;
    const frontmatter = { name: match[1]!, description: match[2]! };
    const root = `skill://container-sandbox/${frontmatter.name}/`;
    const files = [{ uri: `${root}SKILL.md`, text: text! }, { uri: `${root}agents/openai.yaml`, text: agents! }];
    for (const file of files) {
      server.registerResource(file.uri, file.uri, { mimeType: 'text/plain' }, async () => ({ contents: [file] }));
    }
    return { uri: files[0]!.uri, frontmatter, files };
  });
  const catalog = async () =>
    Promise.all(skills.map(async ({ uri, frontmatter, files }) => ({
      uri,
      frontmatter,
      resources: await Promise.all(files.map(async (file) => ({
        uri: file.uri,
        digest: `sha256:${
          new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(file.text))).toHex()
        }`,
      }))),
    })));
  server.server.setRequestHandler(
    'skills/list',
    { params: z.object({ cursor: z.undefined().optional() }) },
    async () => ({ skills: await catalog() }),
  );
  server.server.setRequestHandler('skills/get', { params: z.object({ uri: z.string() }) }, async ({ uri }) => {
    const skill = (await catalog()).find((entry) => entry.uri === uri);
    if (!skill) throw new ProtocolError(-32602, 'Unknown skill URI');
    return { skill };
  });
}
