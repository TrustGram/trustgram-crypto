import { defineConfig } from "@playwright/test"

export default defineConfig({
    testDir: "./tests",
    use: {
        browserName: "chromium"
    },
    reporter: [
        ["list"],
        ["monocart-reporter", {
            name: "TrustGram Crypto Coverage",
            outputFile: "coverage/index.html",
            coverage: {
                entryFilter: (entry: any) => entry.url.includes("dist/crypto.js"),
                sourceFilter: (sourcePath: string) => sourcePath.includes("src/"),
                reports: [
                    ["v8"],
                    ["console-summary"]
                ]
            }
        }]
    ],
    webServer: {
        command: "npx serve . -p 3000 --no-clipboard",
        url: "http://localhost:3000",
        reuseExistingServer: !process.env.CI
    }
})
