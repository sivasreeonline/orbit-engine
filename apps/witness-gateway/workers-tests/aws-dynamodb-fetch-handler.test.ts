import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { describe, expect, it, vi } from "vitest";
import { createFetchDynamoDBRequestHandler } from "../src/provider/aws-dynamodb-witness-provider-adapter";

describe("DynamoDB AWS SDK Fetch transport in workerd", () => {
  it("sends signed DynamoDB JSON requests through the Worker Fetch API", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify({
        Item: {
          PK: { S: "scope#test" },
          SK: { S: "HEAD" },
        },
      }), {
        status: 200,
        headers: {
          "content-type": "application/x-amz-json-1.0",
          "x-amzn-requestid": "workerd-fetch-handler-test",
        },
      })
    );
    vi.stubGlobal("fetch", fetchMock);
    const client = new DynamoDBClient({
      region: "us-east-1",
      endpoint: "https://dynamodb.test",
      credentials: {
        accessKeyId: "synthetic-test-access-key",
        secretAccessKey: "synthetic-test-secret-key",
      },
      requestHandler: createFetchDynamoDBRequestHandler(),
    });

    try {
      const result = await client.send(new GetItemCommand({
        TableName: "synthetic-witness-table",
        Key: {
          PK: { S: "scope#test" },
          SK: { S: "HEAD" },
        },
        ConsistentRead: true,
      }));
      expect(result.Item?.PK?.S).toBe("scope#test");
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [requestUrl, requestInit] = fetchMock.mock.calls[0]!;
      expect(String(requestUrl)).toBe("https://dynamodb.test/");
      expect(requestInit?.method).toBe("POST");
      expect(new Headers(requestInit?.headers).get("x-amz-target")).toBe("DynamoDB_20120810.GetItem");
      expect(String(requestInit?.body)).toContain("synthetic-witness-table");
      expect(new Headers(requestInit?.headers).get("authorization")).toContain("AWS4-HMAC-SHA256");
    } finally {
      client.destroy();
      vi.unstubAllGlobals();
    }
  });
});
