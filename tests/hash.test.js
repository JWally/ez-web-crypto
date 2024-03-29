import EZ_WEB_CRYPTO from "../index";
const ezcrypto = new EZ_WEB_CRYPTO;

test("simple hash testing", async () => {
    expect(await ezcrypto.HASH("SHA-256","data")).toBe("Om6weQ85rIfJTzhWst0sXREOaBFgImGpqSPTuyOtyLc=");
});
