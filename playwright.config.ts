import { defineConfig } from "@playwright/test"

export default defineConfig({
    testDir: "./tests",
    use: {
        browserName: "chromium"
    },
    webServer: {
        command: "npx serve . -p 3000 --no-clipboard",
        url: "http://localhost:3000",
        reuseExistingServer: !process.env.CI
    }
})
