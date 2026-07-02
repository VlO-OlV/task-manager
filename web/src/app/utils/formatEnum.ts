export const formatEnum = (enumValue: string) => {
  return `${enumValue[0]}${enumValue.slice(1).toLowerCase()}`
}