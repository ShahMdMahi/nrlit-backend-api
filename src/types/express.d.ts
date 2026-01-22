declare namespace Express {
  interface Request {
    id: string;
    useragent: useragent.UserAgentInfo;
    device: {
      ipAddress: string;
      country: string;
      countryCode: string;
      region: string;
      regionName: string;
      city: string;
      zip: string;
      lat: string;
      lon: string;
      timezone: string;
      isp: string;
      org: string;
      as: string;
      userAgent: string;
      fingerprint: string;
      deviceName: string;
      deviceBrand: string;
      deviceModel: string;
      osName: string;
      osVersion: string;
      browserName: string;
      browserVersion: string;
      browserEngine: string;
      cpuArch: string;
      deviceType: DeviceType;
    };
  }
}
