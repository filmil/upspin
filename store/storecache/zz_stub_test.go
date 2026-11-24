package storecache

const failedDirName = "storewritebackfailed"
const failedReasonSuffix = ".error"

func isPermanent(err error) bool { return false }
