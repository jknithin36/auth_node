import QRcode from "qrcode";

const otpAuthUrl = process.argv[2];

if (!otpAuthUrl) {
  throw new Error("pass otpAuthUrl as argument");
}

async function main() {
  await QRcode.toFile("totp.png", otpAuthUrl);
  console.log("Qr Saved");
}

main()
  .catch((err) => console.log(err))
  .finally(() => process.exit(1));
