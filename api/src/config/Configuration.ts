export default () => ({
    port: parseInt(process.env.PORT, 10) || 3000,
    secret: process.env.SECRET,
    jwt: {
        ttl: '86400s',
    },
});